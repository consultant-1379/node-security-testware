package com.ericsson.nms.security.nscs.utils;

import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.CXP_RELATIVE_PATH;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Command;
import net.schmizz.sshj.xfer.FileSystemFile;

/**
 * @author enmadmin
 */
//TODO (ekeimoo): This class is very specific for the cloud NetSim in that the ip address of NetSim is hardcoded.
//TODO (ekeimoo): RemoteObjectHandler in TAF could be used to retrieve and upload files
//TODO (ecappie): We'll replace with RemoteObjectHandler.
@SuppressWarnings({"PMD.LawOfDemeter"})
public final class NetsimUtils {

    public static final String SCRIPT = "install_patch.sh";
    private static final Logger log = LoggerFactory.getLogger(NetsimUtils.class);
    private static final String ADDRESS_NETSIM = "192.168.0.2";
    private static final String CREDENTIAL_NETSIM = "netsim";
    private static final String LS_L = "ls -l";
    private static final String DIR_SCRIPT = "inst/";
    public static final String RM_SCRIPT = "rm -f " + DIR_SCRIPT + SCRIPT;
    private static final String DIR_PATCHES = DIR_SCRIPT + "patches/";
    private static final String LS_L_PATCHES = LS_L + " " + DIR_PATCHES;
    private static final String KEY_FOR_RELEASE = "inst -> /netsim/";
    private static final String ZIP_EXT = ".zip";
    public static final String RM_ZIP_PATCH = "rm -f" + " " + DIR_PATCHES + "{}" + ZIP_EXT;
    public static final String NETSIM_URL = "http://netsim.lmera.ericsson.se/tssweb/patches/{}" + ZIP_EXT;
    private static final String CHMOD_SCRIPT = "chmod +x " + DIR_SCRIPT + SCRIPT;
    private static final String SRC_PATH_SCRIPT = "netsim";
    private static final String INSTALL_PATCH = "./" + DIR_SCRIPT + SCRIPT + " {} []";
    private static final String KEY_WORD_SUBSYSTEM = "{}";
    private static final String KEY_WORD_SQUARE = "[]";

    private NetsimUtils() {
    }

    public static void wget(final String urlNetsim, final String item) throws IOException {
        final URL url = new URL(urlNetsim.replace(KEY_WORD_SUBSYSTEM, item));
        final InputStream in = url.openStream();
        final String dest = System.getProperty("user.home") + File.separator + item + ZIP_EXT;
        final OutputStream os = new FileOutputStream(new File(dest));
        final byte[] buffer = new byte[1024];
        int nBytesRead;
        while ((nBytesRead = in.read(buffer)) != -1) {
            os.write(buffer, 0, nBytesRead);
        }
        os.flush();
        os.close();
        in.close();
    }

    public static void downloadFile(final String item) throws IOException, ClassNotFoundException {
        final String src = System.getProperty("user.home") + File.separator + item + ZIP_EXT;
        scpUpload(src, DIR_PATCHES);
    }

    public static boolean downloadScript(final String script) throws IOException {
        boolean isSucces = false;
        final File fsource = new File("");
        final String src = fsource.getCanonicalPath() + CXP_RELATIVE_PATH + Utils.getSourcePath() + SRC_PATH_SCRIPT + File.separator + script;
        scpUpload(src, DIR_SCRIPT);
        final String result = sshRemoteCommand(CHMOD_SCRIPT);
        if (result != null) {
            isSucces = true;
        }
        return isSucces;
    }

    public static boolean removeLocalFile(final String item) {
        boolean isRemoved = false;
        final File file = new File(System.getProperty("user.home") + File.separator + item + ZIP_EXT);
        if (file.isFile()) {
            isRemoved = file.delete();
        }
        return isRemoved;
    }

    public static void scpUpload(final String src, final String dest) throws IOException {
        final SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect(ADDRESS_NETSIM);
        try {
            ssh.authPassword(CREDENTIAL_NETSIM, CREDENTIAL_NETSIM);
            ssh.useCompression();
            ssh.newSCPFileTransfer().upload(new FileSystemFile(src), dest);
        } finally {
            ssh.disconnect();
        }
    }

    public static boolean installPatch(final String release, final String item) throws IOException {
        boolean isSuccess = false;
        final String command = INSTALL_PATCH.replace(KEY_WORD_SUBSYSTEM, release).replace(KEY_WORD_SQUARE, item);
        final String result = sshRemoteCommand(command);
        if (result != null) {
            isSuccess = true;
            log.debug("installed patch [{}]", item);
        }
        return isSuccess;
    }

    public static boolean removeRemoteFile(final String command, final String item) throws IOException, ClassNotFoundException {
        final String result = sshRemoteCommand(command.replace(KEY_WORD_SUBSYSTEM, item));
        return result != null;
    }

    public static boolean removeRemoteScript(final String command) throws IOException {
        final String result = sshRemoteCommand(command);
        return result != null;
    }

    public static String findRelease() throws IOException {
        final String result = sshRemoteCommand(LS_L);
        if (result != null) {
            return foundRelease(result);
        } else {
            return null;
        }
    }

    public static boolean findAlreadyPatch(final String item) throws IOException {
        boolean isAlready = false;
        final String result = sshRemoteCommand(LS_L_PATCHES.replace(KEY_WORD_SUBSYSTEM, item));
        if (result != null) {
            final String foundObj = foundObject(result, item);
            if (foundObj != null) {
                isAlready = true;
            }
        }
        return isAlready;
    }

    private static String sshRemoteCommand(final String command) throws IOException {
        String result = null;
        final SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect(ADDRESS_NETSIM);
        try {
            ssh.authPassword(CREDENTIAL_NETSIM, CREDENTIAL_NETSIM);
            try (Session session = ssh.startSession()) {
                final Command cmd = session.exec(command);
                result = IOUtils.readFully(cmd.getInputStream()).toString();
                cmd.join(5, TimeUnit.SECONDS);
                if (cmd.getExitStatus() != 0) {
                    result = null;
                }
            }
        } finally {
            ssh.disconnect();
        }
        return result;
    }

    private static String foundObject(final String str, final String keyWord) {
        String key = null;
        final Matcher m = Pattern.compile("(" + keyWord + "\n*)").matcher(str);
        if (m.find()) {
            key = (new StringTokenizer(m.group(), "\n")).nextToken();
        }
        return key;
    }

    private static String foundRelease(final String str) {
        String key = null;
        final Matcher m = Pattern.compile("(" + KEY_FOR_RELEASE + "*)").matcher(str);
        if (m.find()) {
            key = str.split(KEY_FOR_RELEASE)[1].split("\n")[0];
        }
        return key;
    }
}
