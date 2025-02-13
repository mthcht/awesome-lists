rule Ransom_Win32_DelShad_2147752507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DelShad!MSR"
        threat_id = "2147752507"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Delete Shadows /All /Quiet" ascii //weight: 2
        $x_2_2 = "shadowcopy delete" ascii //weight: 2
        $x_2_3 = "delete catalog - quiet" ascii //weight: 2
        $x_1_4 = "how to recover.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DelShad_DB_2147772995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DelShad.DB!MTB"
        threat_id = "2147772995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe delete shadows /all" ascii //weight: 2
        $x_2_2 = "Data recovery.hta" ascii //weight: 2
        $x_2_3 = "FindFirstFileA" ascii //weight: 2
        $x_2_4 = "FindNextFileA" ascii //weight: 2
        $x_1_5 = "@tutanota.com" ascii //weight: 1
        $x_1_6 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_DelShad_SC_2147774145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DelShad.SC!MTB"
        threat_id = "2147774145"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 00 6f 00 75 00 72 00 [0-21] 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00}  //weight: 1, accuracy: Low
        $x_1_2 = {59 6f 75 72 [0-21] 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21}  //weight: 1, accuracy: Low
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = "encrypted files on your computer" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

