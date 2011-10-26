#
# Copyright (C) 2011 by moe@busyloop.net
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
module Net
  module SSH
    # Net::SSH::Simple is a simple wrapper around Net::SSH and Net::SCP.
    # 
    # @example
    #   # Block Syntax (synchronous)
    #   Net::SSH::Simple.sync do
    #     r = ssh 'example1.com', 'echo "Hello World."'
    #     puts r.stdout    #=> "Hello World."
    #     puts r.exit_code #=> 0
    #
    #     scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #   end
    #
    # @example
    #   # Block Syntax (asynchronous)
    #   t1 = Net::SSH::Simple.async do
    #     scp_ul 'example1.com', '/tmp/local_foo', '/tmp/remote_bar'
    #     ssh    'example3.com', 'echo "Hello World A."'
    #   end
    #   t2 = Net::SSH::Simple.async do
    #     scp_dl 'example6.com', '/tmp/remote_foo', '/tmp/local_bar'
    #     ssh    'example7.com', 'echo "Hello World B."'
    #   end
    #   r1 = t1.value # wait for t1 to finish and grab return value
    #   r2 = t2.value # wait for t1 to finish and grab return value
    #
    #   puts r1.stdout #=> "Hello World A."
    #   puts r2.stdout #=> "Hello World B."
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
    #       r = scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #       if r.success and r.sent == r.total
    #         puts "Success! Uploaded #{r.sent} of #{r.total} bytes."
    #       end
    #
    #       r = scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #       if r.success and r.sent == r.total
    #         puts "Success! Downloaded #{r.sent} of #{r.total} bytes."
    #       end
    #     end
    #   rescue Net::SSH::Simple::Error => e
    #     puts "Something bad happened!"
    #     puts e          # Human readable error
    #     puts e.wrapped  # Original Exception
    #     puts e.result   # Net::SSH::Simple::Result
    #   end
    #
    # @example
    #   # Error Handling with Block Syntax (asynchronous)
    #   #
    #   # Exceptions are raised inside your thread.
    #   # You are free to handle them or pass them outwards.
    #
    #   a = Net::SSH::Simple.async do
    #     begin
    #       ssh    'example1.com', 'echo "Hello World."'
    #       scp_ul 'example2.com', '/tmp/local_foo', '/tmp/remote_bar'
    #       scp_dl 'example3.com', '/tmp/remote_foo', '/tmp/local_bar'
    #     rescue Net::SSH::Simple::Error => e
    #       # return our exception to the parent thread
    #       e
    #     end
    #   end
    #   r = a.value # Wait for thread to finish and capture result
    #
    #   unless r.is_a? Net::SSH::Simple::Result
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
    #     puts e.wrapped  # Original Exception
    #     puts e.result   # Net::SSH::Simple::Result (partial result)
    #   ensure
    #     s.close # don't forget the clean up!
    #   end
    #
    # @example
    #   # Parameters
    #   Net::SSH::Simple.sync do
    #     ssh('example1.com', 'echo "Hello World."',
    #         {:user => 'tom', :password => 'jerry', :port => 1234})
    #   end
    #
    #   # Parameter inheritance
    #   Net::SSH::Simple.sync({:user => 'tom', :port => 1234}) do
    #     # Both commands will inherit :user and :port
    #     ssh('example1.com', 'echo "Hello World."', {:password => 'jerry'})
    #     scp_ul('example2.com', '/tmp/a', '/tmp/a', {:password => 's3cr3t'})
    #   end
    #
    # @example
    #   # Timeout handling
    #   #
    #   # Note: The timeout applies to each command independently.
    #   # Hint: Set timeout=0 to disable, default is 60
    #   begin
    #     Net::SSH::Simple.sync({:timeout => 5}) do
    #       ssh('example1.com', 'sleep 1')  # I will (probably) succeed!
    #       ssh('example2.com', 'sleep 60') # I will fail :(
    #     end
    #   rescue Net::SSH::Simple::Error => e
    #     puts e.result.timed_out #=> true
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
    # @example
    #   #
    #   # Here be dragons: Using the event-API for a stdin->stdout pipeline
    #   #
    #   r = Net::SSH::Simple.sync do
    #     # open a shell
    #     ssh('localhost', '/bin/sh') do |e,c,d|
    #       # e = :start, :stdout, :stderr, :exit_code, :exit_signal or :finish
    #       # c = our Net::SSH::Connection::Channel instance
    #       # d = data for this event
    #       case e
    #         # :start is triggered exactly once per connection
    #         when :start
    #           # we can send data using Channel#send_data
    #           c.send_data("echo 'hello stdout'\n")
    #           c.send_data("echo 'hello stderr' 1>&2\n")
    #           # don't forget to eof when done feeding!
    #           c.eof!
    #
    #         # :stdout is triggered when there's stdout data from remote.
    #         # by default the data is also appended to result[:stdout].
    #         # you may return :no_append as seen below to avoid that.
    #         when :stdout
    #           # read the input line-wise (it *will* arrive fragmented!)
    #           (@buf ||= '') << d
    #           while line = @buf.slice!(/(.*)\r?\n/)
    #             puts line #=> "hello stdout"
    #           end
    #           :no_append
    #
    #         # :stderr is triggered when there's stderr data from remote.
    #         # by default the data is also appended to result[:stderr].
    #         # you may return :no_append as seen below to avoid that.
    #         when :stderr
    #           # read the input line-wise (it *will* arrive fragmented!)
    #           (@buf ||= '') << d
    #           while line = @buf.slice!(/(.*)\r?\n/)
    #             puts line #=> "hello stderr"
    #           end
    #           :no_append
    #
    #         # :exit_code is triggered when the remote process exits normally.
    #         # it does *not* trigger when the remote process exits by signal!
    #         when :exit_code
    #           puts d #=> 0
    #
    #         # :exit_signal is triggered when the remote is killed by signal.
    #         # this would normally raise a Net::SSH::Simple::Error but
    #         # we suppress that here by returning :no_raise
    #         when :exit_signal
    #           puts d  # won't fire in this example, could be "TERM"
    #           :no_raise
    #
    #         # :finish triggers after :exit_code when the command exits normally.
    #         # it does *not* trigger when the remote process exits by signal!
    #         when :finish
    #           puts "we are finished!"
    #       end
    #     end
    #   end
    #
    #   # Our Result has been populated normally, except for
    #   # :stdout and :stdin (because we used :no_append).
    #   puts r           #=> Net::SSH::Simple::Result
    #   puts r.exit_code #=> 0
    #   puts r.stdout    #=> ''
    #   puts r.stderr    #=> ''
    #
    #
    # @author moe@busyloop.net
    #
    class Simple
      include Blockenspiel::DSL

      #
      # Result of the current Net::SSH::Simple::Operation.
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
      def self.ssh(*args, &block)
        s = self.new
        r = s.ssh(*args, &block)
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
      #
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
      # @param [Block] &block Progress callback (optional)
      # @return [Net::SSH::Simple::Result] Result
      #
      def scp_ul(host, src, dst, opts={}, &block)
        opts = @opts.merge(opts)
        scp(:upload, host, src, dst, opts, &block)
      end

      #
      # SCP download from a remote host.
      # The underlying Net::SSH::Simple instance will re-use
      # existing connections for optimal performance.
      # 
      # @param [String] host Destination hostname or ip-address
      # @param [String] cmd  Shell command to execute
      # @param opts (see Net::SSH::Simple#ssh)
      # @param [Block] &block Progress callback (optional)
      # @return [Net::SSH::Simple::Result] Result
      # @see Net::SSH::Simple#scp_ul
      #
      def scp_dl(host, src, dst, opts={}, &block)
        opts = @opts.merge(opts)
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
      # @param [Block]  &block Use the event-API (see example above)
      # @param [Hash]   opts SSH options
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
      #  a hash of key/value pairs to add to the new connection's properties
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
      # @option opts [Integer] :timeout (60)
      #  connection timeout. this is enforced by Net::SSH::Simple.
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
      def ssh(host, cmd, opts={}, &block)
        opts = @opts.merge(opts)
        with_session(host, opts) do |session|
          @result = Result.new(
            { :op => :ssh, :host => host, :cmd => cmd, :start_at => Time.new,
              :opts => opts, :stdout => '', :stderr => '', :success => nil 
            } )

          channel = session.open_channel do |chan|
            chan.exec cmd do |ch, success|
              @result[:success] = success
              ch.on_data do |c, data|
                r = block.call(:stdout, ch, data) if block
                @result[:stdout] += data.to_s unless r == :no_append
              end
              ch.on_extended_data do |c, type, data|
                r = block.call(:stderr, ch, data) if block
                @result[:stderr] += data.to_s unless r == :no_append
              end
              ch.on_request('exit-status') do |c, data|
                exit_code = data.read_long
                block.call(:exit_code, ch, exit_code) if block
                @result[:exit_code] = exit_code
              end
              ch.on_request('exit-signal') do |c, data|
                exit_signal = data.read_string
                r = block.call(:exit_signal, ch, exit_signal) if block
                @result[:exit_signal] = exit_signal
                @result[:success] = false
                unless r == :no_raise
                  raise "Killed by SIG#{@result[:exit_signal]}"
                end
              end
              block.call(:start, ch, nil) if block
            end
          end
          channel.wait
          @result[:finish_at] = Time.new
          block.call(:finish, channel, nil) if block
          @result
        end
      end

      dsl_methods false

      def initialize(opts={})
        @opts     = opts
        @sessions = {}
        @result   = Result.new
      end

      #
      # Spawn a Thread to perform a sequence of ssh/scp operations.
      # 
      # @param [Block] block 
      # @param opts (see Net::SSH::Simple#ssh)
      # @return [Thread] Thread executing the SSH-Block.
      #
      def self.async(opts={}, &block)
        Thread.new do
          self.sync(opts, &block)
        end
      end

      #
      # Perform a sequence of ssh/scp operations.
      #
      # @param opts (see Net::SSH::Simple#ssh)
      # @return [Net::SSH::Simple::Result] Result
      #
      def self.sync(opts={}, &block)
        s = self.new(opts)
        r = Blockenspiel.invoke(block, s)
        s.close
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
      def with_session(host, opts={:timeout => 60}, &block)
        begin
          Timeout.timeout(opts[:timeout]) do
            session = @sessions[host.hash] = @sessions[host.hash] ||\
              Net::SSH.start(*[host, opts[:user], opts])
            block.call(session)
          end
        rescue => e
          opts[:password].gsub!(/./,'*') if opts.include? :password
          @result[:exception] = e
          @result[:success] = false
          @result[:timed_out] = true
          @result[:finish_at] = Time.new
          raise Net::SSH::Simple::Error, [e, @result]
        end
      end

      def scp(mode, host, src, dst, opts={}, &block)
        @result = Result.new(
          { :op => :scp, :host => host, :opts => opts, :cmd => :scp_dl,
            :start_at => Time.new, :src => src, :dst  => dst, :success => false
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
      # Error that occured during a Net::SSH::Simple operation.
      #
      class Error < RuntimeError
        # Reference to the underlying Exception
        attr_reader :wrapped

        # {Net::SSH::Simple::Result} of the interrupted operation.
        attr_reader :result

        def initialize(msg, e=$!)
          super(msg)
          @wrapped = e
          @result  = msg[1]
        end

        def to_s
          "#{super[0]} @ #{super[1]}"
        end
      end

      #
      # Result of a Net::SSH::Simple operation.
      #
      # @attr [String] host Hostname/IP address
      # @attr [Symbol] op :ssh or :scp
      # @attr [String] cmd Shell command (SSH only)
      # @attr [Time] start_at Operation start timestamp
      # @attr [Time] finish_at Operation finish timestamp
      # @attr [Boolean] timed_out Set to true if the operation timed out
      # @attr [String] stdout Output to stdout (SSH only)
      # @attr [String] stderr Output to stderr (SSH only)
      # @attr [boolean] success
      # @attr [String] exit_code UNIX exit code of the remote command (SSH only)
      # @attr [Integer] total Size of requested file (in bytes, SCP only)
      # @attr [Integer] sent Number of bytes transferred (SCP only)
      # @attr [String] exit_signal
      #   Only present if the remote command terminated due to a signal (SSH only)
      #
      class Result < Hashie::Mash; end
    end
  end
end

