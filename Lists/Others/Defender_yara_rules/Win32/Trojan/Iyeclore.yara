rule Trojan_Win32_Iyeclore_A_2147627163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iyeclore.A!dll"
        threat_id = "2147627163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iyeclore"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 73 73 74 67 67 66 2e 64 6c 6c 00 53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 73 73 72 62 64 74 2e 64 6c 6c 00 53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00}  //weight: 1, accuracy: High
        $x_10_3 = {d5 d2 b2 bb b5 bd b7 fe ce f1 c6 f7 00}  //weight: 10, accuracy: High
        $x_10_4 = {4d 61 78 74 68 6f 6e 00}  //weight: 10, accuracy: High
        $x_10_5 = {54 65 6e 63 65 6e 74 20 54 72 61 76 65 6c 65 72 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Iyeclore_A_2147627164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iyeclore.A"
        threat_id = "2147627164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iyeclore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 06 76 05 e8 ?? ?? ?? ff 40 8b 04 85 ?? ?? ?? ?? 89 45 c0 c6 45 c4 0b 0f b7 45 f6 89 45 c8 c6 45 cc 00 0f b7 45 f4 48 83 f8 0b 76 05}  //weight: 1, accuracy: Low
        $x_1_2 = {44 52 56 00 64 42 61 74 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "frm_IExplcreMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iyeclore_C_2147709404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iyeclore.C!bit"
        threat_id = "2147709404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iyeclore"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "function ClickAD(adcode){lnk = document.getElementById(\"adid\"); if(lnk!=null){lnk.href=adcode;lnk.click();}}" ascii //weight: 1
        $x_1_2 = {8b 45 fc 8b 08 ff 51 ?? ba ?? ?? ?? ?? 8b 45 fc 8b 08 ff 51 ?? ba ?? ?? ?? ?? 8b 45 fc 8b 08 ff 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Iyeclore_GMQ_2147892855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iyeclore.GMQ!MTB"
        threat_id = "2147892855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iyeclore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2d 46 31 37 34 31 31 38 33 36 36 32 35 7d 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "$Iexplcre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

