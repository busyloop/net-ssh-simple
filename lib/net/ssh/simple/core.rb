module Net
  module SSH
    # Net::SSH::Simple is a simple wrapper around Net::SSH and Net::SCP.
    # 
    # @example
    #   # Block Syntax (synchronous)
    #   Net::SSH::Simple.sync do
    #     ssh    'example1.com', 'echo "Hello World."'
    #     scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #   end
    #
    # @example
    #   # Block Syntax (asynchronous)
    #   a = Net::SSH::Simple.async do
    #     ssh    'example1.com', 'echo "Hello World."'
    #     scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #   end
    #   b = Net::SSH::Simple.async do
    #     ssh    'example4.com', 'echo "Hello World."'
    #     scp_ul 'example5.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     scp_dl 'example6.com', '/tmp/remote_foo', '/tmp/local_bar'
    #   end
    #   a.value # Wait for thread A to finish and capture result
    #   b.value # Wait for thread B to finish and capture result
    #
    # @example
    #   # Using an instance
    #   s = Net::SSH::Simple.new
    #   s.ssh    'example1.com', 'echo "Hello World."'
    #   s.scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #   s.scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #   s.close
    #
    # @example
    #   # Using no instance
    #   # Note: This will create a new connection for each operation!
    #   #       Use instance- or block-syntax for better performance.
    #   Net::SSH::Simple.ssh    'example1.com', 'echo "Hello World."'
    #   Net::SSH::Simple.scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #   Net::SSH::Simple.scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #
    # @example
    #   # Error Handling with Block Syntax (synchronous)
    #   begin
    #     Net::SSH::Simple.sync do
    #       r = ssh    'example1.com', 'echo "Hello World."'
    #       if r.success and r.stdout == 'Hello World.'
    #         puts "Success! I Helloed World."
    #       end
    #
    #       scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #       if r.success and r.sent == r.total
    #         puts "Success! Uploaded #{r.sent} of #{r.total} bytes."
    #       end
    #
    #       scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #       if r.success and r.sent == r.total
    #         puts "Success! Downloaded #{r.sent} of #{r.total} bytes."
    #       end
    #     end
    #   rescue Net::SSH::Simple::Error => e
    #     puts "Something bad happened!"
    #     puts e          # Human readable error
    #     puts e.wrapped  # Original Exception from Net::SSH
    #     puts e.context  # Config that triggered the error
    #   end
    #
    # @example
    #   # Error Handling with Block Syntax (asynchronous)
    #   #
    #   # Exceptions are thrown inside your thread.
    #   # You are free to handle them or pass them outwards.
    #   #
    #
    #   a = Net::SSH::Simple.async do
    #     begin
    #       ssh    'example1.com', 'echo "Hello World."'
    #       scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #       scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #     rescue Net::SSH::Result => e
    #       # return our exception to the parent thread
    #       e
    #     end
    #   end
    #   r = a.value # Wait for thread to finish and capture result
    #
    #   unless r.is_a? Net::SSH::Result
    #     puts "Something bad happened!"
    #     puts r
    #   end
    #
    # @example
    #   # Error Handling with an instance
    #   s = Net::SSH::Simple.new
    #   begin
    #     r = s.ssh    'example1.com', 'echo "Hello World."'
    #     if r.success and r.stdout == 'Hello World.'
    #       puts "Success! I Helloed World."
    #     end
    #
    #     r = s.scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     if r.success and r.sent == r.total
    #       puts "Success! Uploaded #{r.sent} of #{r.total} bytes."
    #     end
    #
    #     r = s.scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #     if r.success and r.sent == r.total
    #       puts "Success! Downloaded #{r.sent} of #{r.total} bytes."
    #     end
    #   rescue Net::SSH::Simple::Error => e
    #     puts "Something bad happened!"
    #     puts e          # Human readable error
    #     puts e.wrapped  # Original Exception from Net::SSH
    #     puts e.context  # Config that triggered the error
    #   ensure
    #     s.close # don't forget the clean up!
    #   end
    #
    # @example
    #   # Parametrizing Net::SSH
    #   Net::SSH::Simple.sync do
    #     ssh('example1.com', 'echo "Hello World."',
    #         {:user => 'tom', :password => 'jerry', :port => 1234})
    #   end
    #
    # @example
    #   # Using the SCP progress callback
    #   Net::SSH::Simple.sync do
    #     scp_ul 'example1.com', '/tmp/local_foo', '/tmp/remote_bar' do |sent, total|
    #       puts "Bytes uploaded: #{sent} of #{total}"
    #     end
    #   end
    #
    # @author moe@busyloop.net
    #
    class Simple
      include Blockenspiel::DSL

      #
      # Result of a Net::SSH::Simple::Operation.
      #
      # @return [Net::SSH::Simple::Result] Result of the current operation
      attr_reader :result

      #
      # Perform ssh command on a remote host and capture the result.
      # This will create a new connection for each invocation.
      #
      # @example
      #   Net::SSH::Simple.ssh('localhost', 'echo Hello').class #=> Net::SSH::Simple::Result
      #
      # @example
      #   Net::SSH::Simple.ssh('localhost', 'echo Hello').stdout #=> "Hello"
      #
      # @param (see Net::SSH::Simple#ssh)
      # @raise [Net::SSH::Simple::Error]
      # @return [Net::SSH::Simple::Result] Result
      def self.ssh(*args)
        s = self.new
        r = s.ssh(*args)
        s.close
        r
      end

      #
      # SCP upload to a remote host.
      # This will create a new connection for each invocation.
      #
      # @example
      #   # SCP Upload
      #   Net::SSH::Simple.scp_ul('localhost', '/tmp/local_foo', '/tmp/remote_bar')
      #
      # @example
      #   # Pass a block to monitor progress
      #   Net::SSH::Simple.scp_ul('localhost', '/tmp/local_foo', '/tmp/remote_bar') do |sent, total|
      #     puts "Bytes uploaded: #{sent} of #{total}"
      #   end
      #
      # @param (see Net::SSH::Simple#scp_ul)
      # @raise [Net::SSH::Simple::Error]
      # @return [Net::SSH::Simple::Result] Result
      def self.scp_ul(*args, &block)
        s = self.new
        r = s.scp_ul(*args, &block)
        s.close
        r
      end

      #
      # SCP download from a remote host.
      # This will create a new connection for each invocation.
      #
      # @example
      #   # SCP Download
      #   Net::SSH::Simple.scp_dl('localhost', '/tmp/remote_foo', '/tmp/local_bar')
      #
      # @example
      #   # Pass a block to monitor progress
      #   Net::SSH::Simple.scp_dl('localhost', '/tmp/remote_foo', '/tmp/local_bar') do |sent, total|
      #     puts "Bytes downloaded: #{sent} of #{total}"
      #   end
      #
      # @param (see Net::SSH::Simple#scp_dl)
      # @raise [Net::SSH::Simple::Error]
      # @return [Net::SSH::Simple::Result] Result
      def self.scp_dl(*args, &block)
        s = self.new
        r = s.scp_dl(*args, &block)
        s.close
        r
      end

      # 
      # SCP upload to a remote host.
      # The underlying Net::SSH::Simple instance will re-use
      # existing connections for optimal performance.
      #
      # @param [String] host Destination hostname or ip-address
      # @param [String] cmd  Shell command to execute
      # @param opts (see Net::SSH::Simple#ssh)
      # @param [Block] block Progress callback (optional)
      # @return [Net::SSH::Simple::Result] Result
      #
      def scp_ul(host, src, dst, opts={}, &block)
        scp(:upload, host, src, dst, opts, &block)
      end

      #
      # SCP download from a remote host.
      # The underlying Net::SSH::Simple instance will re-use
      # existing connections for optimal performance.
      # 
      # @param [String] host Destination hostname or ip-address
      # @param [String] cmd  Shell command to execute
      # @param [Hash]   opts Parameters for the underlying Net::SSH
      # @param [Block] block Progress callback (optional)
      # @return [Net::SSH::Simple::Result] Result
      # @see Net::SSH::Simple#scp_ul
      #
      def scp_dl(host, src, dst, opts={}, &block)
        scp(:download, host, src, dst, opts, &block)
      end

      #
      # Perform SSH operation on a remote host and capture the result.
      # The underlying Net::SSH::Simple instance will re-use
      # existing connections for optimal performance.
      #
      # @return [Net::SSH::Simple::Result] Result
      # @param [String] host Destination hostname or ip-address
      # @param [String] cmd  Shell command to execute
      # @param [Hash]   opts Parameters for the underlying Net::SSH
      # @option opts [Array] :auth_methods
      #  an array of authentication methods to try
      #
      # @option opts [String] :compression
      #  the compression algorithm to use,
      #  or true to use whatever is supported.
      #
      # @option opts [Number] :compression_level
      #  the compression level to use when sending data
      #
      # @option opts [String/boolean] :opts (true)
      #  set to true to load the default OpenSSH opts files
      #  (~/.ssh/opts, /etc/ssh_opts), or to false to not load them,
      #  or to a file-name (or array of file-names) to load those
      #  specific configuration files.
      #
      # @option opts [Array] :encryption
      #  the encryption cipher (or ciphers) to use
      #
      # @option opts [boolean] :forward_agent
      #  set to true if you want the SSH agent connection to be forwarded
      #
      # @option opts [String/Array] :global_known_hosts_file 
      #  (['/etc/ssh/known_hosts','/etc/ssh/known_hosts2'])
      #  the location of the global known hosts file.
      #  Set to an array if you want to specify multiple
      #  global known hosts files.
      #
      # @option opts [String/Array] :hmac
      #  the hmac algorithm (or algorithms) to use
      #
      # @option opts [String] :host_key
      #  the host key algorithm (or algorithms) to use
      #
      # @option opts [String] :host_key_alias
      #  the host name to use when looking up or adding a host to a known_hosts dictionary file
      #
      # @option opts [String] :host_name
      #  the real host name or IP to log into. This is used instead of the host parameter,
      #  and is primarily only useful when specified in an SSH configuration file.
      #  It lets you specify an alias, similarly to adding an entry in /etc/hosts but
      #  without needing to modify /etc/hosts.
      #
      # @option opts [String/Array] :kex
      #  the key exchange algorithm (or algorithms) to use
      #
      # @option opts [Array] :keys
      #  an array of file names of private keys to use for publickey and hostbased authentication
      #
      # @option opts [Array] :key_data
      #  an array of strings, with each element of the array being a raw private key in PEM format.
      #
      # @option opts [boolean] :keys_only
      #  set to true to use only private keys from keys and key_data parameters, even if
      #  ssh-agent offers more identities. This option is intended for situations where
      #  ssh-agent offers many different identites.
      #
      # @option opts [Logger] :logger
      #  the logger instance to use when logging
      #
      # @option opts [boolean/:very] :paranoid
      #  either true, false, or :very, specifying how strict host-key verification should be
      #
      # @option opts [String] :passphrase (nil)
      #  the passphrase to use when loading a private key (default is nil, for no passphrase)
      #
      # @option opts [String] :password
      #  the password to use to login
      #
      # @option opts [Integer] :port
      #  the port to use when connecting to the remote host
      #
      # @option opts [Hash] :properties
      #  a hash of key/value pairs to add to the new connection’s properties
      #  (see Net::SSH::Connection::Session#properties)
      #
      # @option opts [String] :proxy
      #  a proxy instance (see Proxy) to use when connecting
      #
      # @option opts [Integer] :rekey_blocks_limit
      #  the max number of blocks to process before rekeying
      #
      # @option opts [Integer] :rekey_limit
      #  the max number of bytes to process before rekeying
      #
      # @option opts [Integer] :rekey_packet_limit
      #  the max number of packets to process before rekeying
      #
      # @option opts [Integer] :timeout
      #  how long to wait for the initial connection to be made
      #
      # @option opts [String] :user
      #  the username to log in as
      #
      # @option opts [String/Array] :user_known_hosts_file
      #  (['~/.ssh/known_hosts, ~/.ssh/known_hosts2'])
      #  the location of the user known hosts file. Set to an array to specify multiple
      #  user known hosts files.
      #
      # @option opts [Symbol] :verbose
      #  how verbose to be (Logger verbosity constants, Logger::DEBUG is very verbose,
      #  Logger::FATAL is all but silent). Logger::FATAL is the default. The symbols
      #  :debug, :info, :warn, :error, and :fatal are also supported and are translated
      #  to the corresponding Logger constant.
      #
      # @see http://net-ssh.github.com/ssh/v2/api/classes/Net/SSH/Config.html
      #      Net::SSH documentation for the 'opts'-hash
      def ssh(host, cmd, opts={})
        with_session(host, opts) do |session|
          @result = Result.new(
            { :host   => host, :cmd    => cmd, :start_at => Time.new,
              :stdout => ''  , :stderr => '' , :success  => nil 
            } )

          channel = session.open_channel do |chan|
            chan.exec cmd do |ch, success|
              @result[:success] = success
              ch.on_data do |c, data|
                @result[:stdout] += data.to_s
              end
              ch.on_extended_data do |c, type, data|
                @result[:stderr] += data.to_s
              end
              ch.on_request('exit-status') do |c, data|
                @result[:exit_code] = data.read_long
              end
              ch.on_request('exit-signal') do |c, data|
                @result[:exit_signal] = data.read_string
                @result[:success] = false
                raise "Killed by SIG#{@result[:exit_signal]}"
              end
            end
          end
          channel.wait
          @result[:finish_at] = Time.new
          @result
        end
      end

      dsl_methods false

      def initialize()
        @sessions = {}
        @result   = Result.new
      end

      #
      # Spawn a Thread to perform a sequence of ssh/scp operations.
      # 
      # @param [Block] block 
      # @return [Thread] Thread executing the SSH-Block.
      #
      def self.async(&block)
        Thread.new do
          self.sync(&block)
        end
      end

      #
      # Perform a sequence of ssh/scp operations.
      #
      # @return [Net::SSH::Simple::Result] Result
      #
      def self.sync(&block)
        b = self.new
        r = Blockenspiel.invoke(block, b)
        b.close
        r
      end

      #
      # Close and cleanup.
      #
      # @return [Net::SSH::Simple::Result] Result
      # 
      def close
        @sessions.values.each do |session|
          session.close
        end
        @result
      end

      private
      def with_session(host, opts, &block)
        begin
          session = @sessions[host.hash] = @sessions[host.hash] ||\
            Net::SSH.start(*[host, opts[:user], opts])
          block.call(session)
        rescue => e
          opts[:password].gsub!(/./,'*') if opts.include? :password
          @result[:exception] = e
          @result[:context] = [host,opts]
          raise Net::SSH::Simple::Error, [e, [host,opts]]
        end
      end

      def scp(mode, host, src, dst, opts={}, &block)
        @result = Result.new(
          { :host   => host, :cmd  => :scp_dl, :start_at => Time.new,
            :src => src    , :dst  => dst    , :success  => false
          } )
        with_session(host, opts) do |session|
          lt = 0
          channel = session.scp.send(mode, src, dst) do |ch, name, sent, total|
            @result[:name] ||= name
            @result[:total] ||= total
            @result[:sent] = sent
            block.call(sent, total) unless block.nil?
          end
          channel.wait
          @result[:finish_at] = Time.new
          @result[:success] = @result[:sent] == @result[:total]
          @result
        end
      end

      #
      # Encapsulates any Errors that may occur
      # during a Net::SSH::Simple operation.
      #
      class Error < RuntimeError
        # Reference to the underlying Net::SSH Exception
        attr_reader :wrapped
        # The opts-hash of the operation that triggered the Error
        attr_reader :context

        def initialize(msg, e=$!)
          super(msg)
          @wrapped = e
          @context = msg[1]
        end

        def to_s
          "#{super[0]} @ #{super[1]}"
        end
      end

      #
      # Result of a Net::SSH::Simple operation.
      #
      # This Mash contains various information that may
      # be relevant to your interests.
      #
      class Result < Hashie::Mash; end
    end
  end
end

