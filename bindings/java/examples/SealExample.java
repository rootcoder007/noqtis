// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
import io.github.rootcoder007.noqtis.Capsule;
import io.github.rootcoder007.noqtis.Sign;
import java.nio.file.Files;
import java.nio.file.Path;

public class SealExample {
  public static void main(String[] args) throws Exception {
    // a folder with some results
    Path d = Files.createTempDirectory("noqtis-java-demo");
    Files.createDirectories(d.resolve("data"));
    Files.writeString(d.resolve("data/in.csv"), "a,b\n1,2\n");
    Files.writeString(d.resolve("report.txt"), "r\n");

    // seal it, then check it with the public key pinned
    Sign.KeyPair k = Sign.keygen("ML-DSA-65");
    Capsule.seal(d, "ML-DSA-65", k.sk(), k.pk(), "{\"project\":\"tutorial\"}");
    Capsule.Opts o = Capsule.Opts.none().withTrust(k.pk());
    Capsule.Report r = Capsule.check(d, o);
    System.out.println("check: " + r.ok() + " (" + r.rows().size() + " checks)");

    // change a file: the check fails and says why
    Files.writeString(d.resolve("report.txt"), "r\nedited\n");
    r = Capsule.check(d, o);
    System.out.println("after edit: " + r.ok());
    for (Capsule.Row row : r.failed()) {
      System.out.println("FAIL " + row.check() + " " + row.detail());
    }
    try (var w = Files.walk(d)) {
      for (Path p : w.sorted(java.util.Comparator.reverseOrder()).toList()) {
        Files.delete(p);
      }
    }
  }
}
