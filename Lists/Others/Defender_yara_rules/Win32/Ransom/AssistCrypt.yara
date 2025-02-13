rule Ransom_Win32_AssistCrypt_MK_2147775945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AssistCrypt.MK!MTB"
        threat_id = "2147775945"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AssistCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@.assist" ascii //weight: 10
        $x_10_2 = "assist.ini" ascii //weight: 10
        $x_5_3 = "cmd.exe /C ping 1.1.1.1 -n 1 -w" ascii //weight: 5
        $x_10_4 = "Ext=log|log1|log2|tmp|sys|bootmgr|dll|theme|bat|cmd|gdcb" ascii //weight: 10
        $x_10_5 = "Prc=w3wp|sql|exchan|node|scan|outlook|thebat|chrome|firefox" ascii //weight: 10
        $x_10_6 = "FName=ASSIST-README.txt" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

