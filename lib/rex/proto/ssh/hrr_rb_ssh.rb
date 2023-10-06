# -*- coding: binary -*-
require 'rex/socket'
require 'hrr_rb_ssh'

###
#
# Rex::Socket overrides for ::HrrRbSsh' use of stdlib sockets
#
###
module HrrRbSsh
class Connection

  @@existing_connection = nil  # Class variable to hold an existing connection
  alias_method :original_initialize, :initialize  # Alias the original initialize method

  def initialize(*args)
    return @@existing_connection if @@existing_connection  # Return existing connection if it exists https://github.com/rapid7/metasploit-framework/issues/18401

    original_initialize(*args)  # Call the original initialize method

    @@existing_connection = self  # Store this connection as the existing connection
  end
end

class GlobalRequestHandler
  def tcpip_forward(message)
    if @connection.permit?(message[:'address to bind'], message[:'port number to bind'], true)
      @logger.info { "starting tcpip-forward" }
      begin
        address_to_bind     = message[:'address to bind']
        port_number_to_bind = message[:'port number to bind']
        id = "#{address_to_bind}:#{port_number_to_bind}"
        server = Rex::Socket::TcpServer.create(
          'LocalHost' => address_to_bind,
          'LocalPort' => port_number_to_bind,
          'Context'   => @connection.options['Context'],
          'Proxies'   => @connection.options['Proxies']
        )
        @tcpip_forward_servers[id] = server
        @tcpip_forward_threads[id] = Thread.new(server){ |server|
          begin
            loop do
              Thread.new(server.accept){ |s|
                @connection.channel_open_start address_to_bind, port_number_to_bind, s
              }
            end
          rescue => e
            @logger.error { [e.backtrace[0], ": ", e.message, " (", e.class.to_s, ")\n\t", e.backtrace[1..-1].join("\n\t")].join }
          end
        }
        @logger.info { "tcpip-forward started" }
      rescue => e
        @logger.warn { "starting tcpip-forward failed: #{e.message}" }
        raise e
      end
    else
      # raise Errno::EACCES
    end
  end
end

class Channel
  class ChannelType
    class DirectTcpip
      def start
        if @connection.permit?(@host_to_connect, @port_to_connect)
          @socket = Rex::Socket::Tcp.create(
            'PeerHost' => @host_to_connect,
            'PeerPort' => @port_to_connect,
            'Context'  => @connection.options['Context'],
            'Proxies'  => @connection.options['Proxies']
          )
          @sender_thread = sender_thread
          @receiver_thread = receiver_thread
        else
          # raise Errno::EACCES
        end
      end
    end
  end
end

end
end
