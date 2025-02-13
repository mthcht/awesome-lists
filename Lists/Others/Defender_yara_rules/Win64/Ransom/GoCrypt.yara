rule Ransom_Win64_GoCrypt_PAA_2147797956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoCrypt.PAA!MTB"
        threat_id = "2147797956"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM" ascii //weight: 1
        $x_1_2 = "hangupkilledlist" ascii //weight: 1
        $x_1_3 = "\\Users\\Public\\Del.cmd" ascii //weight: 1
        $x_1_4 = "\\Del.cmd\\Log.cmd\\README." ascii //weight: 1
        $x_1_5 = "\\ProgramData\\microsoft.exe" ascii //weight: 1
        $x_1_6 = "channeldecrypttool77@gmail.com" ascii //weight: 1
        $x_1_7 = "-Inf-inf.Id-.bat.cmd.com.exe.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

