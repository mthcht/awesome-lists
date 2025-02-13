rule HackTool_Linux_Linikatz_A_2147895594_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.A"
        threat_id = "2147895594"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "gcore -o" wide //weight: 2
        $x_1_2 = "cp " wide //weight: 1
        $x_1_3 = "/var/lib/sss" wide //weight: 1
        $x_1_4 = "/run/ipa/ccaches" wide //weight: 1
        $x_1_5 = "/var/lib/dirsrv" wide //weight: 1
        $x_1_6 = "/etc/dirsrv" wide //weight: 1
        $x_1_7 = "/var/lib/softhsm" wide //weight: 1
        $x_1_8 = "/etc/pki" wide //weight: 1
        $x_1_9 = "/etc/ipa" wide //weight: 1
        $x_1_10 = "/etc/sssd" wide //weight: 1
        $x_1_11 = "/var/opt/quest" wide //weight: 1
        $x_1_12 = "/etc/opt/quest" wide //weight: 1
        $x_1_13 = "/var/lib/pbis" wide //weight: 1
        $x_1_14 = "/etc/pbis" wide //weight: 1
        $x_1_15 = "/var/lib/samba" wide //weight: 1
        $x_1_16 = "/var/cache/samba" wide //weight: 1
        $x_1_17 = "/etc/samba" wide //weight: 1
        $x_1_18 = "/etc/krb5.conf" wide //weight: 1
        $x_1_19 = "/etc/krb5.keytab" wide //weight: 1
        $x_1_20 = "/tmp/krb5" wide //weight: 1
        $x_100_21 = {6c 00 69 00 6e 00 69 00 6b 00 61 00 74 00 7a 00 2e 00 29 05 05 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Linikatz_B_2147895595_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.B"
        threat_id = "2147895595"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 74 00 72 00 69 00 6e 00 67 00 73 00 20 00 6c 00 69 00 6e 00 69 00 6b 00 61 00 74 00 7a 00 2e 00 29 05 05 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Linikatz_D_2147895596_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.D"
        threat_id = "2147895596"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ps -aeo ruser,rgroup,pid,ppid,args" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Linikatz_E_2147895597_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.E"
        threat_id = "2147895597"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "egrep" wide //weight: 5
        $x_1_2 = "libkrb5" wide //weight: 1
        $x_1_3 = "libldap" wide //weight: 1
        $x_5_4 = {2f 00 70 00 72 00 6f 00 63 00 2f 00 29 05 05 00 2f 00 6d 00 61 00 70 00 73 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Linikatz_F_2147895598_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.F"
        threat_id = "2147895598"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sed -e s/.*cachedPassword.*\\$6\\$/\\$6\\$/g -e s/\\\\00lastCached.*//g" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Linikatz_C_2147916733_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Linikatz.C"
        threat_id = "2147916733"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Linikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "grep -E MAPI|\\$6\\$" wide //weight: 10
        $x_10_2 = "egrep -A 1 DN=NAME" wide //weight: 10
        $x_10_3 = "egrep lwsmd|lw-" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

