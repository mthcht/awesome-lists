rule TrojanSpy_AndroidOS_Raddex_YA_2147757597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Raddex.YA!MTB"
        threat_id = "2147757597"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Raddex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hey Rad9" ascii //weight: 1
        $x_1_2 = "Raddex_" ascii //weight: 1
        $x_1_3 = "as_Root" ascii //weight: 1
        $x_1_4 = "tekc@PsetyBeliF" ascii //weight: 1
        $x_1_5 = "You caused an error Mr.R@dd3x" ascii //weight: 1
        $x_1_6 = "HmzaContacts" ascii //weight: 1
        $x_1_7 = "HmzaShell" ascii //weight: 1
        $x_1_8 = "</HAMZA_DELIMITER_STOP>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Raddex_GV_2147787666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Raddex.GV!MTB"
        threat_id = "2147787666"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Raddex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/example/chat_app_securii3772021" ascii //weight: 2
        $x_1_2 = "CCMyInAdminCheck" ascii //weight: 1
        $x_1_3 = "### RAT is Killed ###" ascii //weight: 1
        $x_1_4 = "Au9dioStrmr" ascii //weight: 1
        $x_1_5 = "/api/public_login_new/" ascii //weight: 1
        $x_1_6 = "HmzCntcts235" ascii //weight: 1
        $x_1_7 = "LocMSG923521" ascii //weight: 1
        $x_1_8 = "Raddix_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

