rule TrojanSpy_MSIL_Hesipy_A_2147717261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hesipy.A"
        threat_id = "2147717261"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hesipy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "202F63206E65747368206669726577616C6C2061646420616C6C6F77656470726F6772616D2070726F6772616D203D2022" wide //weight: 1
        $x_1_2 = "5C73656375726974797363616E2E657865" wide //weight: 1
        $x_1_3 = "5C537465616D417070446174612E766466" wide //weight: 1
        $x_1_4 = "5C50617373776F7264732E747874" wide //weight: 1
        $x_1_5 = "5C4D6963726F736F66745C6C6F67" wide //weight: 1
        $x_1_6 = "3C7469746C653E4C6F677320" wide //weight: 1
        $x_1_7 = "5B235B204B65796C6F67676572207374617274656420" wide //weight: 1
        $x_1_8 = "4C6F6773206172652067657474696E672073656E6420286576657279203130206D696E2920" wide //weight: 1
        $x_1_9 = "4E6F204B65796C6F672066696C6520666F756E642120" wide //weight: 1
        $x_1_10 = "55706C6F616420284C6F6773293A20" wide //weight: 1
        $x_1_11 = "687474703A2F2F30763372666C30772E636F6D2F6F766572666C6F772E657865" wide //weight: 1
        $x_1_12 = "7777772E616C657862656E736F6E736869702E636F6D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

