rule Ransom_Win32_Nevada_A_2147842068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nevada.A!dha"
        threat_id = "2147842068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nevada"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEVADA" ascii //weight: 1
        $x_1_2 = "Failed to create ransom note" ascii //weight: 1
        $x_1_3 = "Couldn't delete shadow copies from volume!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nevada_A_2147844300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nevada.A"
        threat_id = "2147844300"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nevada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BZb3VyIGZpbGVzIHdlcmUgc3RvbGVuIGFuZCBlbmNyeXB0ZWQ" ascii //weight: 2
        $x_2_2 = "S0+IFBheSBhIHJhbn" ascii //weight: 2
        $x_2_3 = "peWQub25pb" ascii //weight: 2
        $x_2_4 = "UgZ29pbmcgdG8gcmVjb3ZlciB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

