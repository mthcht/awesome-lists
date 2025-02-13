rule Trojan_Win32_Buzus_H_2147645563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buzus.H"
        threat_id = "2147645563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 81 38 4d 5a 75 ?? 60 89 85 ?? ?? ?? ?? 8b d0 8b d8 03 40 3c 03 58 78 89 9d ?? ?? ?? ?? 8d 9d ?? ?? ?? ?? 8d bd ?? ?? ?? ?? 8b 33 89 b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? ab 83 c3 04 83 3b 00}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 45 94 04 00 02 80 c7 45 8c 0a 00 00 00 ba ?? ?? ?? ?? 8d 4d d0 ff 15 ?? ?? ?? ?? 8d 55 d0 52 8d 45 9c 50 e8 ?? ?? ?? ?? 8d 4d 8c 51 8d 55 9c 52}  //weight: 2, accuracy: Low
        $x_1_3 = "Gbtsm_RE.vbp" wide //weight: 1
        $x_1_4 = "DJ_Sun.vbp" wide //weight: 1
        $x_1_5 = "Ersms_JK.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Buzus_EB_2147836641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buzus.EB!MTB"
        threat_id = "2147836641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ckiyduomugvmtqresvugmmloezj" wide //weight: 1
        $x_1_2 = "Acerbate" wide //weight: 1
        $x_1_3 = "vnagxnwgrb" ascii //weight: 1
        $x_1_4 = "accidence" ascii //weight: 1
        $x_1_5 = "melancholiac" ascii //weight: 1
        $x_1_6 = "kolinsky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Buzus_BD_2147836687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buzus.BD!MTB"
        threat_id = "2147836687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 10 a7 38 08 00 2b 33 71 b5 94 90 3c 61 4f 3c 6f 41 a8 48 2c a5 5b ef bf 92 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71}  //weight: 2, accuracy: High
        $x_2_2 = {34 00 37 00 34 00 32 00 35 00 34 00 34 00 34 00 34 00 39 00 35 00 33 00 00 00 5f 5f 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

