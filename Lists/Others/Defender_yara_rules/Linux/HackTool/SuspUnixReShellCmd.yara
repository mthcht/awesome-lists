rule HackTool_Linux_SuspUnixReShellCmd_E_2147765565_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.E"
        threat_id = "2147765565"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 65 00 72 00 6c 00 [0-32] 2d 00 65 00 [0-32] 75 00 73 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {65 00 78 00 65 00 63 00 [0-2] 28 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_1_3 = "pf_inet" wide //weight: 1
        $x_1_4 = "sock_stream" wide //weight: 1
        $x_1_5 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-2] 28 00 [0-80] 2c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 00 6f 00 63 00 6b 00 61 00 64 00 64 00 72 00 5f 00 69 00 6e 00 [0-2] 28 00 [0-80] 2c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "inet_aton" wide //weight: 1
        $x_1_8 = "open" wide //weight: 1
        $n_80_9 = "127.0.0.1" wide //weight: -80
        $n_80_10 = "localhost" wide //weight: -80
        $n_80_11 = "0.0.0.0" wide //weight: -80
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_G_2147765566_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.G"
        threat_id = "2147765566"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pf_inet" wide //weight: 1
        $x_1_2 = "sock_stream" wide //weight: 1
        $x_10_3 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-2] 28 00 [0-80] 2c 00}  //weight: 10, accuracy: Low
        $x_10_4 = {73 00 6f 00 63 00 6b 00 61 00 64 00 64 00 72 00 5f 00 69 00 6e 00 [0-2] 28 00 [0-80] 2c 00}  //weight: 10, accuracy: Low
        $x_1_5 = "inet_aton" wide //weight: 1
        $x_1_6 = "open" wide //weight: 1
        $n_80_7 = "127.0.0.1" wide //weight: -80
        $n_50_8 = "localhost" wide //weight: -50
        $n_80_9 = "0.0.0.0" wide //weight: -80
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_C_2147765682_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.C"
        threat_id = "2147765682"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 00 77 00 6b 00 20 00 42 00 45 00 47 00 49 00 4e 00 [0-2] 7b 00}  //weight: 10, accuracy: Low
        $x_5_2 = "/inet/tcp/0/" wide //weight: 5
        $x_5_3 = "/inet/udp/0/" wide //weight: 5
        $n_50_4 = "127.0.0.1" wide //weight: -50
        $n_50_5 = "localhost" wide //weight: -50
        $n_50_6 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspUnixReShellCmd_D_2147765683_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.D"
        threat_id = "2147765683"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 [0-32] 2d 00 63 00 [0-32] 69 00 6d 00 70 00 6f 00 72 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 63 00 61 00 6c 00 6c 00 [0-2] 28 00 [0-2] 5b 00 [0-4] 2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_1_3 = "af_inet" wide //weight: 1
        $x_1_4 = "sock_stream" wide //weight: 1
        $x_1_5 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-1] 28 00 [0-1] 28 00 [0-80] 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = "os.dup2" wide //weight: 1
        $n_80_7 = "127.0.0.1" wide //weight: -80
        $n_80_8 = "localhost" wide //weight: -80
        $n_80_9 = "0.0.0.0" wide //weight: -80
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_F_2147765684_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.F"
        threat_id = "2147765684"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ">& /dev/tcp/" wide //weight: 10
        $x_10_2 = ">& /dev/udp/" wide //weight: 10
        $x_1_3 = "sh -i" wide //weight: 1
        $x_1_4 = "0>&1" wide //weight: 1
        $n_50_5 = "127.0.0.1" wide //weight: -50
        $n_50_6 = "localhost" wide //weight: -50
        $n_50_7 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspUnixReShellCmd_I_2147765709_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.I"
        threat_id = "2147765709"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 00 3e 00 [0-2] 2f 00 64 00 65 00 76 00 2f 00 74 00 63 00 70 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3c 00 3e 00 [0-2] 2f 00 64 00 65 00 76 00 2f 00 75 00 64 00 70 00 2f 00}  //weight: 2, accuracy: Low
        $x_10_3 = "sh -c" wide //weight: 10
        $x_1_4 = "exec" wide //weight: 1
        $x_1_5 = "<&" wide //weight: 1
        $x_1_6 = ">&" wide //weight: 1
        $n_50_7 = "127.0.0.1" wide //weight: -50
        $n_50_8 = "localhost" wide //weight: -50
        $n_50_9 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspUnixReShellCmd_J_2147766184_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.J"
        threat_id = "2147766184"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "TCPSocket.new(" wide //weight: 5
        $x_5_2 = "IO.popen(" wide //weight: 5
        $x_5_3 = {69 00 6f 00 [0-2] 7c 00}  //weight: 5, accuracy: Low
        $x_5_4 = {70 00 72 00 69 00 6e 00 74 00 [0-2] 69 00 6f 00 2e 00 72 00 65 00 61 00 64 00 [0-2] 7d 00 [0-2] 65 00 6e 00 64 00}  //weight: 5, accuracy: Low
        $x_1_5 = "ruby" wide //weight: 1
        $x_1_6 = "-rsocket" wide //weight: 1
        $x_1_7 = "-e" wide //weight: 1
        $x_1_8 = "-ropenssl" wide //weight: 1
        $n_50_9 = "127.0.0.1" wide //weight: -50
        $n_50_10 = "localhost" wide //weight: -50
        $n_50_11 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspUnixReShellCmd_K_2147766185_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.K"
        threat_id = "2147766185"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "lua" wide //weight: 5
        $x_5_2 = "socket" wide //weight: 5
        $x_5_3 = "connect" wide //weight: 5
        $x_5_4 = "receive" wide //weight: 5
        $x_5_5 = {69 00 6f 00 [0-2] 2e 00 [0-2] 70 00 6f 00 70 00 65 00 6e 00}  //weight: 5, accuracy: Low
        $x_1_6 = "send" wide //weight: 1
        $x_1_7 = "close" wide //weight: 1
        $x_1_8 = "-e" wide //weight: 1
        $n_60_9 = "127.0.0.1" wide //weight: -60
        $n_60_10 = "localhost" wide //weight: -60
        $n_60_11 = "0.0.0.0" wide //weight: -60
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_L_2147766186_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.L"
        threat_id = "2147766186"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openssl" wide //weight: 1
        $x_1_2 = "s_client" wide //weight: 1
        $x_1_3 = "-quiet" wide //weight: 1
        $x_1_4 = "-connect" wide //weight: 1
        $x_1_5 = "do sh && break;" wide //weight: 1
        $x_1_6 = "done 2>&1" wide //weight: 1
        $x_1_7 = "sh -c" wide //weight: 1
        $n_50_8 = "127.0.0.1" wide //weight: -50
        $n_50_9 = "localhost" wide //weight: -50
        $n_50_10 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_M_2147766187_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.M"
        threat_id = "2147766187"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telnet" wide //weight: 1
        $x_1_2 = "do sh && break;" wide //weight: 1
        $x_1_3 = "done 2>&1" wide //weight: 1
        $x_1_4 = "sh -c" wide //weight: 1
        $n_50_5 = "127.0.0.1" wide //weight: -50
        $n_50_6 = "localhost" wide //weight: -50
        $n_50_7 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_O_2147766754_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.O"
        threat_id = "2147766754"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 62 00 69 00 6e 00 2f 00 [0-4] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_1_2 = "sh -c" wide //weight: 1
        $x_1_3 = "mkfifo " wide //weight: 1
        $x_1_4 = "mknod " wide //weight: 1
        $x_1_5 = "nc " wide //weight: 1
        $x_1_6 = "telnet " wide //weight: 1
        $x_1_7 = "2>&1" wide //weight: 1
        $x_1_8 = "0<" wide //weight: 1
        $n_50_9 = "127.0.0.1" wide //weight: -50
        $n_50_10 = "localhost" wide //weight: -50
        $n_50_11 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspUnixReShellCmd_A_2147767057_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.A"
        threat_id = "2147767057"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "while" wide //weight: 1
        $x_1_2 = "export" wide //weight: 1
        $x_10_3 = {65 00 76 00 61 00 6c 00 20 00 24 00 28 00 77 00 68 00 6f 00 69 00 73 00 20 00 2d 00 68 00 20 00 [0-32] 20 00 2d 00 70 00}  //weight: 10, accuracy: Low
        $n_50_4 = "127.0.0.1" wide //weight: -50
        $n_50_5 = "localhost" wide //weight: -50
        $n_50_6 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Linux_SuspUnixReShellCmd_P_2147926566_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUnixReShellCmd.P"
        threat_id = "2147926566"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUnixReShellCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 79 00 74 00 68 00 6f 00 6e 00 [0-32] 2d 00 63 00 [0-32] 69 00 6d 00 70 00 6f 00 72 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-6] 62 00 61 00 73 00 68 00}  //weight: 10, accuracy: Low
        $x_10_3 = {70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 [0-2] 28 00 [0-6] 73 00 68 00}  //weight: 10, accuracy: Low
        $x_1_4 = "af_inet" wide //weight: 1
        $x_1_5 = "sock_stream" wide //weight: 1
        $x_1_6 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-1] 28 00 [0-1] 28 00 [0-80] 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = "os.dup2" wide //weight: 1
        $n_80_8 = "127.0.0.1" wide //weight: -80
        $n_80_9 = "localhost" wide //weight: -80
        $n_80_10 = "0.0.0.0" wide //weight: -80
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

