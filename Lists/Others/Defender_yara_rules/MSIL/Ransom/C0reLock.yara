rule Ransom_MSIL_C0reLock_AMTB_2147971023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/C0reLock!AMTB"
        threat_id = "2147971023"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "C0reLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Hacking\\C0reLock\\Application\\c0relock\\obj\\Release\\c0relock.pdb" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "C:\\C0reLock\\encrypted_files.txt" ascii //weight: 1
        $x_1_4 = "All files on this system have been encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

