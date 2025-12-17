rule Trojan_MacOS_AmosStealz_A_2147951805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.A!MTB"
        threat_id = "2147951805"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami" wide //weight: 1
        $x_1_2 = "/tmp/.pass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealz_B_2147951806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.B!MTB"
        threat_id = "2147951806"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "electrun" wide //weight: 1
        $x_1_2 = "exodus" wide //weight: 1
        $x_1_3 = "Dogecoin" wide //weight: 1
        $x_1_4 = "Coinomi" wide //weight: 1
        $x_1_5 = ")readwrite(profile &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealz_D_2147951807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.D!MTB"
        threat_id = "2147951807"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ")telegram(writemind" wide //weight: 1
        $x_1_2 = ")encryptFlag(" wide //weight: 1
        $x_1_3 = ")do shell script" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealz_E_2147951808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.E!MTB"
        threat_id = "2147951808"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "do shell script" wide //weight: 1
        $x_1_2 = "echo $((RANDOM %" wide //weight: 1
        $x_1_3 = "system_profiler" wide //weight: 1
        $x_1_4 = "writeText" wide //weight: 1
        $x_1_5 = "system attribute" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_AmosStealz_F_2147951809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.F!MTB"
        threat_id = "2147951809"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptFlag" wide //weight: 1
        $x_1_2 = "do shell script" wide //weight: 1
        $x_1_3 = "send_data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealz_G_2147951810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.G!MTB"
        threat_id = "2147951810"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getpwd(username" wide //weight: 1
        $x_1_2 = "checkvalid(username" wide //weight: 1
        $x_1_3 = "display dialog" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealz_Z_2147959603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealz.Z!MTB"
        threat_id = "2147959603"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -s" wide //weight: 1
        $x_1_2 = "$(echo " wide //weight: 1
        $x_1_3 = "| base64 -d" wide //weight: 1
        $x_1_4 = "| bash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

