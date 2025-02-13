rule Ransom_Win32_Cryakl_A_2147726244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryakl.A"
        threat_id = "2147726244"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryakl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_2_2 = "write you country to dorispackman@tuta.io" ascii //weight: 2
        $x_1_3 = "asshole" ascii //weight: 1
        $x_1_4 = "Pay for decrypt" ascii //weight: 1
        $x_1_5 = "{ENCRYPTENDED}" ascii //weight: 1
        $x_1_6 = "{ENCRYPTSTART}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cryakl_G_2147759634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryakl.G!MSR"
        threat_id = "2147759634"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryakl"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<div>To do this, please send your unique ID to the contacts below.</div>" ascii //weight: 1
        $x_1_2 = "The longer you wait, the higher will become the decryption key price" ascii //weight: 1
        $x_1_3 = "<div>Before payment, we can decrypt three files for free" ascii //weight: 1
        $x_1_4 = "<title>CryLock</title>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryakl_PAA_2147809535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryakl.PAA!MTB"
        threat_id = "2147809535"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryakl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asshole" ascii //weight: 1
        $x_1_2 = "README.txt" wide //weight: 1
        $x_1_3 = "helpxm72.beget.tech" ascii //weight: 1
        $x_1_4 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

