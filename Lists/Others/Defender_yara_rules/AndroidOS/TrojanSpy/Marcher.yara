rule TrojanSpy_AndroidOS_Marcher_C_2147836997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Marcher.C!MTB"
        threat_id = "2147836997"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Marcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "load_sms.php" ascii //weight: 1
        $x_1_2 = "set_card.php" ascii //weight: 1
        $x_1_3 = "set_commerzbank.php" ascii //weight: 1
        $x_1_4 = "sms_hook" ascii //weight: 1
        $x_1_5 = "au.com.nab.mobile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Marcher_D_2147844118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Marcher.D!MTB"
        threat_id = "2147844118"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Marcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "load_sms" ascii //weight: 1
        $x_1_2 = "hideme" ascii //weight: 1
        $x_1_3 = "setOnCardNumber" ascii //weight: 1
        $x_1_4 = "i<<mW8>>n<<mW8>>j<<mW8>>e<<mW8>>c<<mW8>>t<<mW8>>s<<mW8>>F<<mW8>>i<<mW8>>l<<mW8>>l<<mW8>>e<<mW8>>d<<mW8>>" ascii //weight: 1
        $x_1_5 = "i<<mW8>>n<<mW8>>t<<mW8>>e<<mW8>>n<<mW8>>t<<mW8>>_<<mW8>>w<<mW8>>i<<mW8>>t<<mW8>>h<<mW8>>_<<mW8>>c<<mW8>>a<<mW8>>r<<mW8>>d<<mW8>>" ascii //weight: 1
        $x_1_6 = "s<<mW8>>e<<mW8>>n<<mW8>>d<<mW8>>_<<mW8>>c<<mW8>>a<<mW8>>r<<mW8>>d<<mW8>>_<<mW8>>n<<mW8>>u<<mW8>>m<<mW8>>b<<mW8>>e<<mW8>>r<<mW8>>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

