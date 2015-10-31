/* -----------------------------------------------------------------------------
 * Copyright (C) 2008 Robert Ernst <robert.ernst@linux-solutions.at>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.io.InputStream;
import java.io.OutputStream;

public final class UdpToTcp {
	public static void main(String[] args) {
		String host = null;
		Integer port = 161;
		Integer udp_port = 161;
		Socket tcp_socket = localhost;
		DatagramSocket udp_socket = null;
		InputStream input_stream = null;
		OutputStream output_stream = null;

		/* Parse commandline arguments */
		try {
			for (int i = 0; i < args.length; i++) {
				int pos =args[i].indexOf(':');
				if (args[i].matches("-udp-port:[0-9]+")) {
					udp_port = Integer.parseInt(args[i].substring(pos + 1));
				} else if (args[i].matches("-port:[0-9]+")) {
					port = Integer.parseInt(args[i].substring(pos + 1));
				} else if (args[i].matches("-host:.+")) {
					host = args[i].substring(pos + 1);
				}
			}
		} catch (Exception e) {
			System.out.println(e);
			System.exit(1);
		}

		/* Open the local UDP socket */
		try {
			udp_socket = new DatagramSocket(udp_port);
		} catch (Exception e) {
			System.out.println(e);
			System.exit(1);
		}

		/* Open the remote TCP socket */
		try {
			tcp_socket = new Socket(host, port);
			input_stream = tcp_socket.getInputStream();
			output_stream = tcp_socket.getOutputStream();
		} catch (Exception e) {
			System.out.println(e);
			System.exit(1);
		}

		/* Forward until the hell freezes */
		System.out.println("forwarding udp:localhost:" + udp_port
			+ " to tcp:" + host + ":" + port);
		while (true) {
			DatagramPacket packet = null;
			byte[] buffer = new byte[2048];

			/* Receive the UDP packet */
			try {
				packet = new DatagramPacket(buffer, buffer.length);
				udp_socket.receive(packet);
			} catch (Exception e) {
				System.out.println(e);
				System.exit(1);
			}
			System.out.println("received UDP packet of " + packet.getLength() + " bytes");

			/* Send the TCP packet */
			try {
				output_stream.write(packet.getData(), 0, packet.getLength());
				output_stream.flush();
			} catch (Exception e) {
				System.out.println(e);
				System.exit(1);
			}
			System.out.println("sent TCP packet");

			/* Receive the TCP packet */
			try {
				int length = input_stream.read(buffer);
				packet.setData(buffer);
				packet.setLength(length);
			} catch (Exception e) {
				System.out.println(e);
				System.exit(1);
			}
			System.out.println("received TCP packet of " + packet.getLength() + " bytes");

			/* Send the UDP packet */
			try {
				udp_socket.send(packet);
			} catch (Exception e) {
				System.out.println(e);
				System.exit(1);
			}
			System.out.println("sent UDP packet");
		}
	}
}

/* vim: ts=4 sw=4 sts=4 nowrap
 */
