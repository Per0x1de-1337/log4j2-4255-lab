import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.util.FilteredObjectInputStream;

import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.MarshalledObject;

/**
 * Minimal stand-in for a serialized-LogEvent receiver: the pattern the Log4j
 * samples' ObjectInputStreamLogEventBridge / TcpSocketServer used before Apache
 * removed the in-core socket server (post-2.8.2). It reads one object per
 * connection through {@link FilteredObjectInputStream} (FOIS), exactly as those
 * receivers did.
 *
 * FOIS overrides resolveClass with a name allowlist, but that allowlist keeps
 * java.rmi.MarshalledObject. A MarshalledObject stores its payload as an opaque
 * byte[], so the resolveClass filter never inspects it. When the object graph is
 * reconstructed, Log4jLogEvent$LogEventProxy.readResolve() rebuilds the message
 * by calling marshalledMessage.get() — and MarshalledObject.get() deserializes
 * those bytes on a FRESH, UNFILTERED ObjectInputStream. Any gadget on the inner
 * stream therefore runs. That readResolve -> .get() call is Log4j's own code; it
 * fires automatically here because the payload's outer class is the real
 * LogEventProxy and log4j-core is on the classpath.
 *
 * The explicit MarshalledObject.get() branch below is belt-and-suspenders: it
 * makes the unfiltered inner-stream deserialization visible even if a payload
 * hands us a bare MarshalledObject instead of wrapping it in a LogEventProxy.
 */
public class Receiver {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 4560;
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress("0.0.0.0", port));
        System.out.println("[receiver] FOIS bridge on 0.0.0.0:" + port
                + "  filter=" + System.getProperty("jdk.serialFilter", "<none>"));
        for (;;) {
            try (Socket s = ss.accept()) {
                System.out.println("[receiver] connection from " + s.getRemoteSocketAddress());
                try (ObjectInputStream in = new FilteredObjectInputStream(s.getInputStream())) {
                    Object o = in.readObject();               // LogEventProxy.readResolve() -> .get() fires here
                    if (o instanceof MarshalledObject) {      // bare MarshalledObject: reproduce .get() ourselves
                        o = ((MarshalledObject<?>) o).get();
                    }
                    if (o instanceof LogEvent) {
                        LogEvent e = (LogEvent) o;
                        System.out.println("[receiver] processed event OK: msg=\""
                                + e.getMessage().getFormattedMessage() + "\"");
                    } else {
                        System.out.println("[receiver] read " + (o == null ? "null" : o.getClass().getName()));
                    }
                } catch (Throwable t) {
                    System.out.println("[receiver] readObject REJECTED/failed: "
                            + t.getClass().getName() + ": " + t.getMessage());
                }
            } catch (Throwable t) {
                System.out.println("[receiver] connection error: " + t);
            }
        }
    }
}
