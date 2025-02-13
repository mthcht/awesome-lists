rule Ransom_Win32_Resq_PAF_2147850154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Resq.PAF!MTB"
        threat_id = "2147850154"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Resq"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 10, accuracy: High
        $x_10_2 = {0b c8 8b 85 ?? ?? ?? ?? 03 c6 03 ca 03 ce 89 85 ?? ?? ?? ?? 8b f0 89 8d ?? ?? ?? ?? c1 c0 07 8b d1 c1 ce 0b 33 f0 c1 ca 0d 8b 85 ?? ?? ?? ?? c1 c8 06}  //weight: 10, accuracy: Low
        $x_1_3 = "NETWORK HAS BEEN PENETRATED" ascii //weight: 1
        $x_1_4 = "encrypted" ascii //weight: 1
        $x_1_5 = "vssadmin.exe delete shadows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

