rule Trojan_MSIL_StubRc_PA_2147760269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StubRc.PA!MTB"
        threat_id = "2147760269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StubRc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ruamotherfuker" ascii //weight: 1
        $x_1_2 = "<@@ENCEXE@@>" wide //weight: 1
        $x_1_3 = "Sp33D Crypter" ascii //weight: 1
        $x_1_4 = "Rusty_v Productions" ascii //weight: 1
        $x_1_5 = {5c 41 6c 78 53 74 75 62 5c 41 6c 78 53 74 75 62 5c 6f 62 6a 5c [0-16] 5c 53 70 33 33 44 20 53 74 75 62 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = "Sp33D Stub.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

