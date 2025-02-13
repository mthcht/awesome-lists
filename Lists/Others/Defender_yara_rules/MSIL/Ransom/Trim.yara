rule Ransom_MSIL_Trim_2147725269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Trim"
        threat_id = "2147725269"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "s test file for proof of decryption MMM Ransomware." ascii //weight: 2
        $x_2_2 = "<title>TripleM Ransomware</title>" ascii //weight: 2
        $x_2_3 = "\\MMM\\obj\\Release\\MMM.pdb" ascii //weight: 2
        $x_2_4 = "MMM.exe" wide //weight: 2
        $x_2_5 = "This is is simulating OS . YOu might delete it permanently." wide //weight: 2
        $x_2_6 = "vssadmin delete shadows /all /quiet" wide //weight: 2
        $x_2_7 = "bcedit.exe /set {default} recovery enabled no" wide //weight: 2
        $x_2_8 = "bcedit.exe /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 2
        $x_2_9 = "del selfdelete.bat" wide //weight: 2
        $x_2_10 = "MMM.Properties.Resources" wide //weight: 2
        $x_2_11 = ".triple_m" wide //weight: 2
        $x_2_12 = "\\RESTORE_triple_m__FILES.html" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

