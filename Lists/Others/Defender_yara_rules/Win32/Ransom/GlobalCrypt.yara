rule Ransom_Win32_GlobalCrypt_PA_2147960689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GlobalCrypt.PA!MTB"
        threat_id = "2147960689"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GlobalCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".9UvK4X" wide //weight: 1
        $x_1_2 = "files encrypted" ascii //weight: 1
        $x_1_3 = ".onion/chat/" wide //weight: 1
        $x_4_4 = {31 d2 8d 44 24 ?? c7 44 24 54 ?? ?? ?? ?? c7 44 24 58 ?? ?? ?? ?? 66 89 54 24 ?? 8d 54 24 ?? 81 30 5a 00 5a 00 83 c0 04 39 d0 75 ?? 31 c0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

