rule Ransom_Win32_Fog_D_2147911917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fog.D"
        threat_id = "2147911917"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "he maximum number of processes has been reached!" ascii //weight: 1
        $x_1_2 = "[-] CryptEncrypt() error, code: %d" ascii //weight: 1
        $x_1_3 = "[!] All task finished, locker exiting." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Fog_MKV_2147914048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fog.MKV!MTB"
        threat_id = "2147914048"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 99 b9 05 00 00 00 f7 f9 33 74 d5 ac 33 7c d5 ?? 8b 55 fc 8b c2 31 30 8d 40 28 31 78 dc 83 e9 01 75 ?? 83 c2 08 8d 71 05 43 89 55 fc 83 6d f8 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Fog_SA_2147927090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fog.SA"
        threat_id = "2147927090"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-nomutex" wide //weight: 10
        $x_10_2 = "-size" wide //weight: 10
        $x_10_3 = "-target" wide //weight: 10
        $x_10_4 = "\\c$" wide //weight: 10
        $n_1000_5 = "msedgewebview2.exe" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

