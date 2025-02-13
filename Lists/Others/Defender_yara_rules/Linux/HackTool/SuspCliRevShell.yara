rule HackTool_Linux_SuspCliRevShell_A_2147783070_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspCliRevShell.A"
        threat_id = "2147783070"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspCliRevShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "socket.socket()" wide //weight: 10
        $x_5_2 = "use Socket" wide //weight: 5
        $x_5_3 = "PF_INET,SOCK_STREAM" wide //weight: 5
        $x_10_4 = "TCPSocket.new(" wide //weight: 10
        $x_5_5 = "jrunscript -e" wide //weight: 5
        $x_5_6 = {6a 00 61 00 76 00 61 00 2e 00 6c 00 61 00 6e 00 67 00 2e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 5, accuracy: Low
        $x_10_7 = "java.net.Socket(" wide //weight: 10
        $x_5_8 = "IO.popen(" wide //weight: 5
        $x_5_9 = {69 00 6f 00 [0-2] 7c 00}  //weight: 5, accuracy: Low
        $x_5_10 = "os.dup2" wide //weight: 5
        $x_5_11 = "(0,1,2)" wide //weight: 5
        $x_5_12 = "getInputStream(" wide //weight: 5
        $x_5_13 = "getOutputStream(" wide //weight: 5
        $x_10_14 = {70 00 72 00 69 00 6e 00 74 00 [0-2] 69 00 6f 00 2e 00 72 00 65 00 61 00 64 00 [0-2] 7d 00}  //weight: 10, accuracy: Low
        $x_5_15 = "open(STDIN,\">" wide //weight: 5
        $x_5_16 = "open(STDOUT,\">" wide //weight: 5
        $x_10_17 = {70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_10_18 = {70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-4] 73 00 68 00 [0-1] 29 00}  //weight: 10, accuracy: Low
        $x_10_19 = {65 00 78 00 65 00 63 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

