rule Ransom_Win64_Eclipse_A_2147981161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Eclipse.A"
        threat_id = "2147981161"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Eclipse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "eclipse\\DefaultIcon" ascii //weight: 5
        $x_1_2 = "Administrator:P@ssw0rd!" ascii //weight: 1
        $x_1_3 = "msaccess,mspub,onenote,vmwp,mms,trueimagehome,schedhlp" ascii //weight: 1
        $x_1_4 = "ootsect.bak,desktop.ini,iconcache.db,ntldr,ntuser.dat,ntuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

