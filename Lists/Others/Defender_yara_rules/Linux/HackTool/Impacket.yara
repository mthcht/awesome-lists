rule HackTool_Linux_Impacket_A_2147765165_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Impacket.A"
        threat_id = "2147765165"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Impacket"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_5_2 = "atexec" wide //weight: 5
        $x_5_3 = "dcomexec" wide //weight: 5
        $x_5_4 = "smbexec" wide //weight: 5
        $x_5_5 = "wmiexec" wide //weight: 5
        $x_5_6 = "psexec" wide //weight: 5
        $x_50_7 = "-hashes " wide //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Impacket_C_2147765342_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Impacket.C"
        threat_id = "2147765342"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Impacket"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "python" wide //weight: 50
        $x_5_2 = "atexec.py " wide //weight: 5
        $x_5_3 = "dcomexec.py " wide //weight: 5
        $x_5_4 = "wmiexec.py " wide //weight: 5
        $x_5_5 = "smbexec.py " wide //weight: 5
        $x_5_6 = "psexec.py " wide //weight: 5
        $x_5_7 = "smbclient.py " wide //weight: 5
        $x_5_8 = "rpcdump.py " wide //weight: 5
        $n_100_9 = "yum " wide //weight: -100
        $n_100_10 = "rm -rf " wide //weight: -100
        $n_100_11 = "rm -f " wide //weight: -100
        $n_100_12 = "/bin/rm -f " wide //weight: -100
        $n_100_13 = "/bin/busybox rm -f " wide //weight: -100
        $n_100_14 = "sha1sum " wide //weight: -100
        $n_100_15 = "sha256sum " wide //weight: -100
        $n_100_16 = "md5sum " wide //weight: -100
        $n_100_17 = "chmod " wide //weight: -100
        $n_100_18 = "chown " wide //weight: -100
        $n_100_19 = "ls " wide //weight: -100
        $n_100_20 = "find " wide //weight: -100
        $n_100_21 = "stat " wide //weight: -100
        $n_100_22 = "du " wide //weight: -100
        $n_100_23 = "grep " wide //weight: -100
        $n_100_24 = "ansible_collections/community/windows/plugins/modules/psexec.py" wide //weight: -100
        $n_100_25 = "site-packages/ansible_collections/community/windows/plugins/modules/psexec.py" wide //weight: -100
        $n_100_26 = "/builds/build/ansible_venv/lib/python" wide //weight: -100
        $n_100_27 = {67 00 72 00 65 00 70 00 20 00 [0-255] 2f 00 6c 00 69 00 62 00 2f 00 70 00 79 00 74 00 68 00 6f 00 6e 00 [0-16] 2f 00 73 00 69 00 74 00 65 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-255] 65 00 78 00 65 00 63 00 2e 00 70 00 79 00}  //weight: -100, accuracy: Low
        $n_100_28 = {66 00 69 00 6e 00 64 00 20 00 [0-255] 2f 00 6c 00 69 00 62 00 2f 00 70 00 79 00 74 00 68 00 6f 00 6e 00 [0-16] 2f 00 73 00 69 00 74 00 65 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-255] 65 00 78 00 65 00 63 00 2e 00 70 00 79 00}  //weight: -100, accuracy: Low
        $n_100_29 = {64 00 75 00 20 00 [0-255] 2f 00 6c 00 69 00 62 00 2f 00 70 00 79 00 74 00 68 00 6f 00 6e 00 [0-16] 2f 00 73 00 69 00 74 00 65 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-255] 65 00 78 00 65 00 63 00 2e 00 70 00 79 00}  //weight: -100, accuracy: Low
        $n_100_30 = {6c 00 73 00 20 00 [0-255] 2f 00 6c 00 69 00 62 00 2f 00 70 00 79 00 74 00 68 00 6f 00 6e 00 [0-16] 2f 00 73 00 69 00 74 00 65 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-255] 65 00 78 00 65 00 63 00 2e 00 70 00 79 00}  //weight: -100, accuracy: Low
        $n_100_31 = {73 00 74 00 61 00 74 00 20 00 [0-255] 2f 00 6c 00 69 00 62 00 2f 00 70 00 79 00 74 00 68 00 6f 00 6e 00 [0-16] 2f 00 73 00 69 00 74 00 65 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-255] 65 00 78 00 65 00 63 00 2e 00 70 00 79 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

