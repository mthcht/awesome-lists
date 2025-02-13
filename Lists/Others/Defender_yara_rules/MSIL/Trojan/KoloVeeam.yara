rule Trojan_MSIL_KoloVeeam_A_2147906295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KoloVeeam.A"
        threat_id = "2147906295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KoloVeeam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "veeam" ascii //weight: 1
        $x_1_2 = "database=veeambackup" ascii //weight: 1
        $x_1_3 = "select [user_name],[password],[description] from [veeambackup].[dbo].[credentials]" ascii //weight: 1
        $x_1_4 = "encrypted pass:" ascii //weight: 1
        $x_1_5 = "decrypted pass:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

