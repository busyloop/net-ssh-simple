require 'cover_me'
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
#   /tmp/ssh_test_in{0,1,2,3,4}
#   /tmp/ssh_test_out{0,1,2,3,4}
#

describe Net::SSH::Simple do
  describe "singleton" do
    before :each do
      (0..4).each do |i|
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

    it "fails gently" do
      lambda {
        Net::SSH::Simple.ssh('localhost', 'true', {:port => 0})
      }.should raise_error(Net::SSH::Simple::Error)

      begin
        Net::SSH::Simple.ssh('localhost', 'true', {:port => 0})
      rescue => e
        e.to_s.should == 'Connection refused - connect(2) @ ["localhost", {:port=>0}]'
      end
    end

    it "returns a result" do
      Net::SSH::Simple.ssh('localhost', 'true').success.should == true
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

    it "uploads via scp" do
      mockback = mock(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = Net::SSH::Simple.scp_ul('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

    it "downloads via scp" do
      mockback = mock(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = Net::SSH::Simple.scp_dl('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end
  end

  describe "instance" do
    before :each do
      @s = Net::SSH::Simple.new

      (0..4).each do |i|
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

    it "uploads via scp" do
      mockback = mock(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = @s.scp_ul('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end

    it "downloads via scp" do
      mockback = mock(:progress_callback)
      mockback.should_receive(:ping).at_least(:once)
      r = @s.scp_dl('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
        mockback.ping
      end
      r.success.should == true
      Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
    end
  end

  describe "synchronous block syntax" do
    it "returns a result" do
      Net::SSH::Simple.sync do
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

    it "uploads via scp" do
      Net::SSH::Simple.sync do
        mockback = mock(:progress_callback)
        mockback.should_receive(:ping).at_least(:once)
        r = scp_ul('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
          mockback.ping
        end
        r.success.should == true
        Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
      end
    end

    it "downloads via scp" do
      Net::SSH::Simple.sync do
        mockback = mock(:progress_callback)
        mockback.should_receive(:ping).at_least(:once)
        r = scp_dl('localhost', '/tmp/ssh_test_in0', '/tmp/ssh_test_out0') do |sent,total|
          mockback.ping
        end
        r.success.should == true
        Digest::MD5.file('/tmp/ssh_test_in0').should == Digest::MD5.file('/tmp/ssh_test_out0')
      end
    end
  end

  describe "asynchronous block syntax" do
    before :each do
      (0..4).each do |i|
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
      (0..4).each do |i|
        t[i] = Net::SSH::Simple.async do
          mockback = mock(:progress_callback)
          mockback.should_receive(:ping).at_least(:once)
          r = nil
          if 0 == i % 2 
            r = scp_dl('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
              mockback.ping
            end
          else
            r = scp_ul('localhost', "/tmp/ssh_test_in#{i}", "/tmp/ssh_test_out#{i}") do |sent,total|
              mockback.ping
            end
          end
          r.success.should == true
          ssh('localhost', "echo hello #{i}")
        end
      end

      (0..4).each do |i|
        r = t[i].value
        r.stdout.should == "hello #{i}\n"
        Digest::MD5.file("/tmp/ssh_test_in#{i}").should == Digest::MD5.file("/tmp/ssh_test_out#{i}")
      end
    end

    it "handles signals" do
      victim = Net::SSH::Simple.async do
        begin
          ssh('localhost', 'sleep 1020304157')
        rescue => e
          e
        end
      end

      killer = Net::SSH::Simple.async do
        ssh('localhost', "pkill -f 'sleep 1020304157'")
      end

      k = killer.value
      k.success.should == true

      v = victim.value
      v.to_s.should == 'Killed by SIGTERM @ ["localhost", {}]'
    end
  end
end
