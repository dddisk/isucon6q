require 'digest/sha1'
require 'json'
require 'net/http'
require 'uri'

require 'erubis'
require 'mysql2'
require 'mysql2-cs-bind'
require 'rack/utils'
require 'sinatra/base'
require 'tilt/erubis'
require 'rack-mini-profiler'
require 'rack-lineprof'
require 'pry'
require 'sinatra/reloader'
require 'redis'

module Isuda
  class Web < ::Sinatra::Base
    enable :protection
    enable :sessions

    set :erb, escape_html: true
    set :public_folder, File.expand_path('../../../../public', __FILE__)
    set :db_user, ENV['ISUDA_DB_USER'] || 'root'
    set :db_password, ENV['ISUDA_DB_PASSWORD'] || ''
    set :dsn, ENV['ISUDA_DSN'] || 'dbi:mysql:db=isuda'
    set :session_secret, 'tonymoris'
    set :isupam_origin, ENV['ISUPAM_ORIGIN'] || 'http://localhost:5050'
    set :isutar_origin, ENV['ISUTAR_ORIGIN'] || 'http://localhost:5001'

    configure :development do
      require 'sinatra/reloader'

      register Sinatra::Reloader
    end

    set(:set_name) do |value|
      condition {
        user_id = session[:user_id]
        if user_id
          user = db.xquery(%| select name from user where id = ? |, user_id).first
          @user_id = user_id
          @user_name = user[:name]
          halt(403) unless @user_name
        end
      }
    end

    set(:authenticate) do |value|
      condition {
        halt(403) unless @user_id
      }
    end

    helpers do
      def redis
  Thread.current[:redis] ||=
    begin
    redis = Redis.new(:path => "/var/run/redis/redis.sock")
    end
  end
      def db
        Thread.current[:db] ||=
          begin
            _, _, attrs_part = settings.dsn.split(':', 3)
            attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
            mysql = Mysql2::Client.new(
              username: settings.db_user,
              password: settings.db_password,
              database: attrs['db'],
              encoding: 'utf8mb4',
              init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
            )
            mysql.query_options.update(symbolize_keys: true)
            mysql
          end
      end

      def register(name, pw)
        #chars = [*'A'..'~']
        #salt = 1.upto(20).map { chars.sample }.join('')
  salt = "aaa"
        #salted_password = encode_with_salt(password: pw, salt: salt)
  newid = redis.incr("USER_NEW_ID")
  redis.set("USER_#{name}_password", pw)
  #redis.set("USER_#{name}_salt", salt)
  redis.set("USER_#{name}_id", newid)
        #db.xquery(%|
        #  INSERT INTO user (name, salt, password, created_at)
        #  VALUES (?, ?, ?, NOW())
        #|, name, salt, salted_password)
        #db.last_id
  newid
      end

      def encode_with_salt(password: , salt: )
        Digest::SHA1.hexdigest(salt + password)
      end

      def is_spam_content(content)
        isupam_uri = URI(settings.isupam_origin)
        res = Net::HTTP.post_form(isupam_uri, 'content' => content)
        validation = JSON.parse(res.body)
        validation['valid']
        ! validation['valid']
      end

      def htmlify(content,re)
        #keywords = db.xquery(%| select keyword from entry order by character_length(keyword) desc |)
        #pattern = keywords.map {|k| Regexp.escape(k[:keyword]) }.join('|')
        kw2hash = {}
        hashed_content = content.gsub(re) {|m|
          matched_keyword = m
          "isuda_#{Digest::SHA1.hexdigest(matched_keyword)}".tap do |hash|
            kw2hash[matched_keyword] = hash
          end
        }
        escaped_content = Rack::Utils.escape_html(hashed_content)
        kw2hash.each do |(keyword, hash)|
          keyword_url = url("/keyword/#{Rack::Utils.escape_path(keyword)}")
          anchor = '<a href="%s">%s</a>' % [keyword_url, Rack::Utils.escape_html(keyword)]
          escaped_content.gsub!(hash, anchor)
        end
        escaped_content.gsub(/\n/, "<br />\n")
      end

      def uri_escape(str)
        Rack::Utils.escape_path(str)
      end

      def load_stars(keyword)
        isutar_url = URI(settings.isutar_origin)
        isutar_url.path = '/stars'
        isutar_url.query = URI.encode_www_form(keyword: keyword)
        body = Net::HTTP.get(isutar_url)
        stars_res = JSON.parse(body)
        stars_res['stars']
      end

      def redirect_found(path)
        redirect(path, 302)
      end
    end

    get '/initialize' do
      db.xquery(%| DELETE FROM entry WHERE id > 7101 |)
      redis.flushall
      system('/usr/bin/redis-cli < /home/isucon/webapp/ruby/userinfo.redis > /dev/null')
      isutar_initialize_url = URI(settings.isutar_origin)
      isutar_initialize_url.path = '/initialize'
      Net::HTTP.get_response(isutar_initialize_url)

      content_type :json
      JSON.generate(result: 'ok')
    end

    get '/', set_name: true do
      per_page = 10
      page = (params[:page] || 1).to_i

      entries = db.xquery(%|
        SELECT * FROM entry
        ORDER BY updated_at DESC
        LIMIT #{per_page}
        OFFSET #{per_page * (page - 1)}
      |)
      entries.each do |entry|
        keyesc = Rack::Utils.escape_path(entry[:keyword])
        data = redis.get("key_"+keyesc)
  if data == nil
            unless @re
                keywords = db.xquery(%| select keyword from entry order by character_length(keyword) desc |)
                pattern = keywords.map {|k| Regexp.escape(k[:keyword]) }.join('|')
                @re = Regexp.new(pattern)
            end
      data = htmlify(entry[:description],@re)
            redis.set("key_"+keyesc,data)
      redis.set(Rack::Utils.escape_path(entry[:description]),keyesc)
  end
  entry[:stars] = redis.lrange "star:#{entry[:keyword]}",0,-1
  entry[:html] = data
      end

      total_entries = db.xquery(%| SELECT count(*) AS total_entries FROM entry |).first[:total_entries].to_i

      last_page = (total_entries.to_f / per_page.to_f).ceil
      from = [1, page - 5].max
      to = [last_page, page + 5].min
      pages = [*from..to]

      locals = {
        entries: entries,
        page: page,
        pages: pages,
        last_page: last_page,
      }
      erb :index, locals: locals
    end

    get '/robots.txt' do
      halt(404)
    end

    get '/register', set_name: true do
      erb :register
    end

    post '/register' do
      name = params[:name] || ''
      pw   = params[:password] || ''
      #puts "register #{name} #{pw}"
      halt(400) if (name == '') || (pw == '')

      user_id = register(name, pw)
      session[:user_id] = user_id

      redirect_found '/'
    end

    get '/login', set_name: true do
      locals = {
        action: 'login',
      }
      erb :authenticate, locals: locals
    end

    post '/login' do
      name = params[:name]
      user = {}
      user[:id] = redis.get("USER_#{params[:name]}_id")
  if user[:id] 
    #puts "redis hit"
    halt(403) unless params[:password] == params[:name]
  else
    #puts "mysql query"
    user = db.xquery(%| select * from user where name = ? |, name).first
          halt(403) unless user
          halt(403) unless user[:password] == encode_with_salt(password: params[:password], salt: user[:salt])
    redis.set("USER_#{name}_password", params[:password])
    redis.set("USER_#{name}_id", user[:id])
  end
#      user[:password] = redis.get("USER_#{params[:name]}_password")
#      user[:salt] = Base64.decode64(redis.get("USER_#{params[:name]}_salt"))
#      halt(403) unless user[:password] == encode_with_salt(password: params[:password], salt: user[:salt])
      session[:user_id] = user[:id]
      redirect_found '/'
    end

    get '/logout' do
      session[:user_id] = nil
      redirect_found '/'
    end

    post '/keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] || ''
      halt(400) if keyword == ''
      description = params[:description]
      halt(400) if is_spam_content(description) || is_spam_content(keyword)

      bound = [@user_id, keyword, description] * 2
      db.xquery(%|
        INSERT INTO entry (author_id, keyword, description, created_at, updated_at)
        VALUES (?, ?, ?, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, updated_at = NOW()
      |, *bound)
      keyesc = Rack::Utils.escape_path(keyword)
      redis.scan_each(:match => "*"+keyesc+"*") do |key|
        kw=redis.get(key)
        if kw != nil && redis.exists("key_"+kw)
    redis.del(key)
    redis.del("key_"+kw)
        end
      end
      redirect_found '/'

    end

    get '/keyword/:keyword', set_name: true do
      keyword = params[:keyword] or halt(400)

      entry = db.xquery(%| select * from entry where keyword = ? |, keyword).first or halt(404)
      entry[:stars] = redis.lrange "star:#{keyword}",0,-1
       keyesc = Rack::Utils.escape_path(entry[:keyword])
       data = redis.get("key_"+keyesc)
       if data == nil
               keywords = db.xquery(%| select keyword from entry order by character_length(keyword) desc |)
               pattern = keywords.map {|k| Regexp.escape(k[:keyword]) }.join('|')
               re = Regexp.new(pattern)
               data = htmlify(entry[:description],re)
               redis.set("key_"+keyesc,data)
               redis.set(Rack::Utils.escape_path(entry[:description]),keyesc)
       end
       entry[:html] = data

      locals = {
        entry: entry,
      }
      erb :keyword, locals: locals
    end

    post '/keyword/:keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] or halt(400)
      is_delete = params[:delete] or halt(400)

      unless db.xquery(%| SELECT * FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end

      db.xquery(%| DELETE FROM entry WHERE keyword = ? |, keyword)

      redirect_found '/'
    end
  end
end
