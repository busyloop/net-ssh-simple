require 'simplecov'
SimpleCov.start

require 'net/ssh/simple'
require 'digest/md5'
require 'securerandom'

#
# In order to run this test-suite you must
# have ssh-access to localhost.
#
# 1. Add your own ssh-key to authorized_keys:
#    cat >>~/.ssh/authorized_keys ~/.ssh/id_rsa.pub
#
# 2. Add something like this to ~/.ssh/config:
#
#    Host localhost
#    User my_name
#    Port 22
#
# The test-suite will (over)write the following files on localhost:
#   /tmp/ssh_test_in*
#   /tmp/ssh_test_out*
#

CONCURRENCY = 16

BENCHMARK_ITER = 10
BENCHMARK_CONCURRENCY = 128

describe Net::SSH::Simple do
  describe "singleton" do
    before :each do
      (0..CONCURRENCY).each do |i|
        begin
          File.unlink(File.join('/tmp', "ssh_test_in#{i}"))
        rescue; end
        begin
          File.unlink(File.join('/tmp', "ssh_test_out#{i}"))
        rescue; end
        File.open(File.join('/tmp', "ssh_test_in#{i}"), 'w') do |fd|
          fd.write(SecureRandom.random_bytes(1024+SecureRandom.random_number(8192)))
        end
      end
    end

    it "enforces idle timeout" do
      raised = false
      begin
        r = Net::SSH::Simple.ssh('localhost', 'sleep 60', {:timeout => 5, :keepalive_interval => 1})
      rescue => e
        raised = true
        e.to_s.should match /^idle timeout @ .*/
        e.result.op == :ssh
        e.result.timed_out.should == true
      end
      raised.should == true
    end

    it "enforces operation timeout on ssh" do
      raised = false
      begin
        r = Net::SSH::Simple.ssh('localhost', 'while true; do echo "buh"; sleep 1; done', {:operation_timeout => 2})
      rescue => e
        raised = true
        e.to_s.should match /^execution expired @ .*/
        e.result.op == :ssh
        e.result.timed_out.should == true
      end
      raised.should == true
    end

    it "enforces operation timeout on scp_put" do
      raised = false
      begin
        r = Net::SSH::Simple.scp_put('localhost', '/tmp/ssh_test_in0',
                                    '/tmp/ssh_test_out0', {:operation_timeout=>1}) \
        do |sent,total|
          sleep 5
        end
      rescue => e
        raised = true
        e.to_s.should match /^execution expired @ .*/
        e.result.op == :ssh
        e.result.timed_out.should == true
      end
      raised.should == true
    end

    it "enforces operation timeout on scp_get" do
      raised = false
      begin
        r = Net::SSH::Simple.scp_get('localhost', '/tmp/ssh_test_in0',
                                    '/tmp/ssh_test_out0', {:operation_timeout=>1}) \
        do |sent,total|
          sleep 5
        end
      rescue => e
        raised = true
        e.to_s.should match /^execution expired @ .*/
        e.result.op == :ssh
        e.result.timed_out.should == true
      end
      raised.should == true
    end

    it "interprets timeout=0 as no timeout" do
      Net::SSH::Simple.ssh('localhost', 'sleep 2', {:timeout => 0})
    end

    it "interprets operation_timeout=0 as no timeout" do
      Net::SSH::Simple.ssh('localhost', 'sleep 2', {:operation_timeout => 0})
    end

    it "fails gently" do
      raised = false
      begin
        Net::SSH::Simple.ssh('localhost', 'true', {:port => 0})
      rescue => e
        raised = true
        e.to_s.should match /^Connection refused - connect\(2\).*/
        e.result.timed_out.should == nil
      end
      raised.should == true
    end

    it "returns a result" do
      Net::SSH::Simple.ssh('localhost', 'true').success.should == true
    end

    it "sends keep-alive" do
      r = Net::SSH::Simple.ssh('localhost', 'sleep 3', {:keepalive_interval=>1})
      (Time.now - r.last_keepalive_at).to_i.should < 3

      r = Net::SSH::Simple.ssh('localhost', 'sleep 3', {:keepalive_interval=>5})
      (Time.now - r.last_keepalive_at).to_i.should > 2
    end

    it "recognizes exit-codes" do
      Net::SSH::Simple.ssh('localhost', 'true').exit_code.should == 0
      Net::SSH::Simple.ssh('localhost', 'false').exit_code.should == 1
    end

    it "reads stdout" do
      Net::SSH::Simple.ssh('localhost', 'echo hello').stdout.should == "hello\n"
      long = Net::SSH::Simple.ssh('localhost', 'seq 1 100000').stdout
      Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
    end

    it "reads stderr" do
      Net::SSH::Simple.ssh('localhost', 'echo hello 1>&2').stderr.should == "hello\n"
      long = Net::SSH::Simple.ssh('localhost', 'seq 1 100000 1>&2').stderr
      Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
    end

    it "uploads via scp_put" do
      mockback = double(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = Net::SSH::Simple.scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

    it "downloads via scp_get" do
      mockback = double(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = Net::SSH::Simple.scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

  end

  describe "instance" do
    before :each do
      @s = Net::SSH::Simple.new

      (0..CONCURRENCY).each do |i|
        begin
          File.unlink(File.join('/tmp', "ssh_test_in#{i}"))
        rescue; end
        begin
          File.unlink(File.join('/tmp', "ssh_test_out#{i}"))
        rescue; end
        File.open(File.join('/tmp', "ssh_test_in#{i}"), 'w') do |fd|
          fd.write(SecureRandom.random_bytes(1024+SecureRandom.random_number(8192)))
        end
      end
    end

    after :each do
      @s.close
    end

    it "returns a result" do
      @s.ssh('localhost', 'true').success.should == true
    end

    it "recognizes exit-codes" do
      @s.ssh('localhost', 'true').exit_code.should == 0
      @s.ssh('localhost', 'false').exit_code.should == 1
    end

    it "reads stdout" do
      @s.ssh('localhost', 'echo hello').stdout.should == "hello\n"
      long = @s.ssh('localhost', 'seq 1 100000').stdout
      Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
    end

    it "reads stderr" do
      @s.ssh('localhost', 'echo hello 1>&2').stderr.should == "hello\n"
      long = @s.ssh('localhost', 'seq 1 100000 1>&2').stderr
      Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
    end

    it "uploads via scp_put" do
      mockback = double(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = @s.scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      r.op.should == :scp
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

    it "downloads via scp_get" do
      mockback = double(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = @s.scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      r.op.should == :scp
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

    it "supports async" do
      a = @s.async do
        ssh('localhost', 'sleep 1; echo hello')
      end
      b = @s.async do
        ssh('localhost', 'sleep 2; echo hella')
      end
      a.value.stdout.should == "hello\n"
      b.value.stdout.should == "hella\n"
    end

  end

  describe "synchronous block syntax" do
    it "returns a result" do
      Net::SSH::Simple.sync do
        ssh('localhost', 'true').success.should == true
        # see coverage-report to see if session#shutdown! was exercised
      end
    end

    it "force closes" do
      Net::SSH::Simple.sync({:close_timeout => true}) do
        ssh('localhost', 'true').success.should == true
      end
    end

    it "recognizes exit-codes" do
      Net::SSH::Simple.sync do
        ssh('localhost', 'true').exit_code.should == 0
        ssh('localhost', 'false').exit_code.should == 1
      end
    end

    it "reads stdout" do
      Net::SSH::Simple.sync do
        ssh('localhost', 'echo hello').stdout.should == "hello\n"
        long = ssh('localhost', 'seq 1 100000').stdout
        Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
      end
    end

    it "reads stderr" do
      Net::SSH::Simple.sync do
        ssh('localhost', 'echo hello 1>&2').stderr.should == "hello\n"
        long = ssh('localhost', 'seq 1 100000 1>&2').stderr
        Digest::MD5.hexdigest(long).should == 'dea9193b768319cbb4ff1a137ac03113'
      end
    end

    it "uploads via scp_put" do
      Net::SSH::Simple.sync do
        mockback = double(:progress_callback)
        mockback.should_receive(:ping).at_least(:once)
        r = scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
          mockback.ping
        end
        r.success.should == true
        Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
      end
    end

    it "downloads via scp_get" do
      Net::SSH::Simple.sync do
        mockback = double(:progress_callback)
        mockback.should_receive(:ping).at_least(:once)
        r = scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
          mockback.ping
        end
        r.success.should == true
        Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
      end
    end

  end

  describe "asynchronous block syntax" do
    before :each do
      (0..CONCURRENCY).each do |i|
        begin
          File.unlink(File.join('/tmp', "ssh_test_in#{i}"))
        rescue; end
        begin
          File.unlink(File.join('/tmp', "ssh_test_out#{i}"))
        rescue; end
        File.open(File.join('/tmp', "ssh_test_in#{i}"), 'w') do |fd|
          fd.write(SecureRandom.random_bytes(1024+SecureRandom.random_number(8192)))
        end
      end
    end

    it "copes with a little concurrency" do
      t = []
      (0..CONCURRENCY).each do |i|
        t[i] = Net::SSH::Simple.async do
          mockback = double(:progress_callback)
          mockback.should_receive(:ping).at_least(:once)
          mockback.should_not_receive(:exception)
          begin
            r = nil
            if 0 == i % 2
              r = scp_get('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
                mockback.ping
              end
            else
              r = scp_put('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
                mockback.ping
              end
            end
            r.success.should == true
            ssh('localhost', "echo hello #{i}")
          rescue => e
            p e
            mockback.exception()
          end
        end
      end

      (0..CONCURRENCY).each do |i|
        r = t[i].value
        r.stdout.should == "hello #{i}\n"
        Digest::MD5.file("/tmp/ssh_test_in#{i}").should == Digest::MD5.file("/tmp/ssh_test_out#{i}")
      end
    end

    it "doesn't break under high concurrency", :benchmark => true do
      iter = 0
      (0..BENCHMARK_ITER).each do
        iter += 1
        t = []
        (0..BENCHMARK_CONCURRENCY).each do |i|
          #t[i] = Net::SSH::Simple.async(:verbose=>Logger::DEBUG) do
          t[i] = Net::SSH::Simple.async do
            mockback = double(:progress_callback)
            mockback.should_receive(:ping).at_least(:once)
            r = nil
            if 0 == i % 2
              r = scp_get('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
                mockback.ping
              end
            else
              r = scp_put('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
                mockback.ping
              end
            end
            r.success.should == true
            ssh('localhost', "echo hello #{i}")
          end
        end

        (0..BENCHMARK_CONCURRENCY).each do |i|
          r = t[i].value
          r.stdout.should == "hello #{i}\n"
          Digest::MD5.file("/tmp/ssh_test_in#{i}").should == Digest::MD5.file("/tmp/ssh_test_out#{i}")
        end
        puts "#{iter}/#{BENCHMARK_ITER}"
      end
    end

    it "handles signals" do
      victim = Net::SSH::Simple.async({:timeout => 10}) do
        begin
          ssh('localhost', 'sleep 1020304157')
        rescue => e
          e
        end
      end

      killer = Net::SSH::Simple.async({:operation_timeout => 5}) do
        sleep 1 while 0 != ssh('localhost', "pgrep -f 'sleep 1020304157'").exit_code
        ssh('localhost', "pkill -f 'sleep 1020304157'")
      end

      k = killer.value
      k.success.should == true
      k.exit_code.should == 0

      v = victim.value
      v.to_s.should match /Killed by SIGTERM @ .*/
    end
  end

  describe "parameter inheritance" do
    it "works with instance syntax" do
      s = Net::SSH::Simple.new({:timeout => 7})
      r = s.ssh('localhost', 'date', {:rekey_packet_limit => 42})
      r.op.should == :ssh
      r.opts[:timeout].should == 7
      r.opts[:rekey_packet_limit].should == 42

      r = s.scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                     {:rekey_packet_limit => 42})
      r.op.should == :scp
      r.opts[:timeout].should == 7
      r.opts[:rekey_packet_limit].should == 42

      r = s.scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                     {:rekey_packet_limit => 42})
      r.op.should == :scp
      r.opts[:timeout].should == 7
      r.opts[:rekey_packet_limit].should == 42

      s.close
    end

    it "works with instance syntax + async" do
      s = Net::SSH::Simple.new({:timeout => 7})
      t = s.async({:operation_timeout => 11}) do
        r = ssh('localhost', 'date', {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42
        r.opts[:operation_timeout].should == 11

        r = scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42
        r.opts[:operation_timeout].should == 11

        r = scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42
        r.opts[:operation_timeout].should == 11

        :happy
      end
      t.value.should == :happy
    end

    it "works with synchronous block syntax" do
      r = Net::SSH::Simple.sync({:timeout => 7}) do
        r = ssh('localhost', 'date', {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

        r = scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

        r = scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

      end
    end

    it "works with asynchronous block syntax" do
      t = Net::SSH::Simple.async({:timeout => 7}) do
        r = ssh('localhost', 'date', {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

        r = scp_put('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

        r = scp_get('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0',
                   {:rekey_packet_limit => 42})
        r.opts[:timeout].should == 7
        r.opts[:rekey_packet_limit].should == 42

        :happy
      end
      t.value.should == :happy
    end
  end

  describe "event api" do
    it "works with singleton syntax" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_receive(:finish).once.ordered
      r = Net::SSH::Simple.ssh('localhost', '/bin/sh') do |e,c,d|
        case e
          when :start
            mockie.start()
            c.send_data("echo 'hello stdout'\n")
            c.eof!
          when :finish
            mockie.finish()
        end
      end
      r.stdout.should == "hello stdout\n"
      r.stderr.should == ''
    end

    it "works with instance syntax" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_receive(:finish).once.ordered
      s =  Net::SSH::Simple.new
      r = s.ssh('localhost', '/bin/sh') do |e,c,d|
        case e
          when :start
            mockie.start()
            c.send_data("echo 'hello stdout'\n")
            c.eof!
          when :finish
            mockie.finish()
        end
      end
      r.stdout.should == "hello stdout\n"
      r.stderr.should == ''
    end

    it "works with synchronous block syntax" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_receive(:finish).once.ordered
      r = Net::SSH::Simple.sync do
        ssh('localhost', '/bin/sh') do |e,c,d|
          case e
            when :start
              mockie.start()
              c.send_data("echo 'hello stdout'\n")
              c.eof!
            when :finish
              mockie.finish()
          end
        end
      end
      r.stdout.should == "hello stdout\n"
      r.stderr.should == ''
    end

    it "works with asynchronous block syntax" do
      t = Net::SSH::Simple.async do
        mockie = double(:callbacks)
        mockie.should_receive(:start).once.ordered
        mockie.should_receive(:finish).once.ordered
        ssh('localhost', '/bin/sh') do |e,c,d|
          case e
            when :start
              mockie.start()
              c.send_data("echo 'hello stdout'\n")
              c.eof!
            when :finish
              mockie.finish()
          end
        end
      end
      r = t.value
      r.stdout.should == "hello stdout\n"
      r.stderr.should == ''
    end

    it "handles long stdin->stdout pipe" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_receive(:exit_code).once.ordered
      mockie.should_receive(:finish).once.ordered
      mockie.should_not_receive(:exit_signal)

      stdout_copy = ''
      a = Net::SSH::Simple.sync do
        i = 0
        r = ssh('localhost', 'sed "s/0/X/g"') do |e,c,d|
          case e
            when :start
              mockie.start()
              (0..16384).each do |i|
                c.send_data("foobar #{i}\n")
              end
              c.eof!
            when :stdout
              stdout_copy << d
              (@buf ||= '') << d
              while line = @buf.slice!(/(.*)\r?\n/)
                line.chop.should == "foobar #{i}".gsub('0','X')
                i += 1
              end
            when :exit_code
              mockie.exit_code()
            when :exit_signal
              mockie.exit_signal()
            when :finish
              mockie.finish()
          end
        end
        r.stdout.should == stdout_copy
        r.stderr.should == ''
      end
    end

    it "handles intermingled stdout/stderr" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_receive(:exit_code).once.ordered
      mockie.should_receive(:finish).once.ordered
      mockie.should_not_receive(:exit_signal)
      a = Net::SSH::Simple.sync do
        stdout_c = 0
        stderr_c = 0
        stdout_copy = ''
        stderr_copy = ''
        r = ssh('localhost', '/bin/sh') do |e,c,d|
          case e
            when :start
              mockie.start()
              (1..420).each do |i|
                c.send_data("echo 'hello stderr' 1>&2\n")
                c.send_data("echo 'hello stdout'\n")
                c.send_data("echo 'HELLO STDERR' 1>&2\n")
                c.send_data("echo 'HELLO STDOUT'\n")
              end
              c.eof!
            when :stdout
              stdout_copy << d
              (@buf ||= '') << d
              while line = @buf.slice!(/(.*)\r?\n/)
                oddeven = stdout_c % 2
                case oddeven
                  when 0
                    line.chop.should == "hello stdout"
                  else
                    line.chop.should == "HELLO STDOUT"
                end
                stdout_c += 1
              end
            when :stderr
              stderr_copy << d
              (@buf ||= '') << d
              while line = @buf.slice!(/(.*)\r?\n/)
                oddeven = stderr_c % 2
                case oddeven
                  when 0
                    line.chop.should == "hello stderr"
                  else
                    line.chop.should == "HELLO STDERR"
                end
                stderr_c += 1
              end
            when :exit_code
              mockie.exit_code()

            when :exit_signal
              mockie.exit_signal()

            when :finish
              stdout_c.should == 840
              stderr_c.should == 840
              mockie.finish()
          end
        end
        # result should be populated
        r.stdout.should == stdout_copy
        r.stderr.should == stderr_copy
        r.exit_code.should == 0
      end
    end

    it "handles signals" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_not_receive(:exit_code)
      mockie.should_receive(:exit_signal).once
      mockie.should_not_receive(:finish)

      victim = Net::SSH::Simple.async do
        begin
          ssh('localhost', 'sleep 1020304157') do |e,c,d|
            case e
              when :start
                mockie.start()
              when :exit_signal
                d.should == 'TERM'
                mockie.exit_signal()
              when :exit_code
                mockie.exit_code()
              when :finish
                mockie.finish()
            end
          end
        rescue => e
          e
        end
      end

      killer = Net::SSH::Simple.async({:operation_timeout => 5}) do
        sleep 1 while 0 != ssh('localhost', "pgrep -f 'sleep 1020304157'").exit_code
        ssh('localhost', "pkill -f 'sleep 1020304157'")
      end

      k = killer.value
      k.success.should == true

      v = victim.value
      v.to_s.should match /Killed by SIGTERM @ .*/
    end

    it "handles signals (:no_raise)" do
      mockie = double(:callbacks)
      mockie.should_receive(:start).once.ordered
      mockie.should_not_receive(:exit_code)
      mockie.should_receive(:exit_signal).once
      mockie.should_receive(:finish).once.ordered

      victim = Net::SSH::Simple.async do
        begin
          ssh('localhost', 'sleep 1020304157') do |e,c,d|
            case e
              when :start
                mockie.start()
              when :exit_signal
                d.should == 'TERM'
                mockie.exit_signal()
                :no_raise
              when :exit_code
                mockie.exit_code()
              when :finish
                mockie.finish()
            end
          end
        rescue => e
          e
        end
      end

      killer = Net::SSH::Simple.async({:operation_timeout => 5}) do
        sleep 1 while 0 != ssh('localhost', "pgrep -f 'sleep 1020304157'").exit_code
        ssh('localhost', "pkill -f 'sleep 1020304157'")
      end


      k = killer.value
      k.success.should == true

      v = victim.value
      v.success.should == false
      v.exit_signal.should == 'TERM'
    end

    it "respects :no_append" do
      r = Net::SSH::Simple.sync do
        stdout_c = 0
        stderr_c = 0
        stdout_copy = ''
        stderr_copy = ''
        ssh('localhost', '/bin/sh') do |e,c,d|
          case e
            when :start
              c.send_data("echo 'hello stderr' 1>&2\n")
              c.send_data("echo 'hello stdout'\n")
              c.send_data("echo 'HELLO STDERR' 1>&2\n")
              c.send_data("echo 'HELLO STDOUT'\n")
              c.eof!
            when :stdout
              :no_append
            when :stderr
              :no_append
          end
        end
      end
      r.stdout.should == ''
      r.stderr.should == ''
    end

  end
end
