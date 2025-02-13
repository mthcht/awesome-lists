rule Trojan_Win32_BirRat_MK_2147780415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BirRat.MK!MTB"
        threat_id = "2147780415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BirRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_2 = "-----END PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Establish HTTP proxy tunnel to %s:%h" ascii //weight: 1
        $x_1_4 = "Kerberos" ascii //weight: 1
        $x_1_5 = "decrypt password" ascii //weight: 1
        $x_1_6 = "Compromise" ascii //weight: 1
        $x_1_7 = "session_id" ascii //weight: 1
        $x_1_8 = "master_key" ascii //weight: 1
        $x_1_9 = "key_arg" ascii //weight: 1
        $x_1_10 = "Bot ID:" ascii //weight: 1
        $x_1_11 = "User:" ascii //weight: 1
        $x_1_12 = "Software\\Sysinternals\\AutoRuns" ascii //weight: 1
        $x_1_13 = "ROOT\\CIMV2" ascii //weight: 1
        $x_1_14 = "xmrmine" ascii //weight: 1
        $x_1_15 = "xmr64_mine_start" ascii //weight: 1
        $x_1_16 = "Clipboard:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

