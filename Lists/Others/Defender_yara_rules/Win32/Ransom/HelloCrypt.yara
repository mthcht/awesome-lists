rule Ransom_Win32_HelloCrypt_MK_2147806026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HelloCrypt.MK!MTB"
        threat_id = "2147806026"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HelloCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$Recycle.Bin" ascii //weight: 1
        $x_1_2 = "\\Hello.txt" ascii //weight: 1
        $x_1_3 = "All files are encrypted" ascii //weight: 1
        $x_1_4 = "decryption cost will be automatically increased" ascii //weight: 1
        $x_1_5 = "your personal id:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

