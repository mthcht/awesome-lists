rule Worm_AndroidOS_Jimoke_A_2147752696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Jimoke.A"
        threat_id = "2147752696"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Jimoke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "file:///android_asset/dd.html" ascii //weight: 5
        $x_2_2 = "http://tiny.cc/JioPrime" ascii //weight: 2
        $x_2_3 = "Lcom/marolemod/bnchodmda/Main2Activity" ascii //weight: 2
        $x_1_4 = "/system/app/Superuser.apk" ascii //weight: 1
        $x_1_5 = "/system/bin/su" ascii //weight: 1
        $x_1_6 = "202787852" ascii //weight: 1
        $x_2_7 = "aSISKSbhFLYE/b9DEBS7d0MDYsx8w8uEfgF5uqzj319w6JNbR52saHDPDYWELWPWrrZZqYxZDWNU/r3G4gbE+iVnyU/1KbohmntJPmq/Q/tc5OJUUUK7lG9WIBuaJqU/y" ascii //weight: 2
        $x_2_8 = "Lcom/marolemod/bnchodmda/newser" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_AndroidOS_Jimoke_B_2147752863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Jimoke.B"
        threat_id = "2147752863"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Jimoke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ThisIsSpartaThisIsSparta" ascii //weight: 5
        $x_5_2 = "aSISKSbhFLYE/b9DEBS7d/TAo/L6+7JWf03j23s9xBys7AQVIkueE1J+0JVwdbbgVq9UL8OXKaSOq49Y0wO3zvFyxqGLD1lT7i2mFtggWiLbVsJe1QHUbpynFGfFnkEUkqpsnvWVnUwgd/2CfYUIUTHg/KyX3XRAe4vQXPl4ty980SYDDOE1xg==" ascii //weight: 5
        $x_5_3 = "DESede" ascii //weight: 5
        $x_1_4 = "SENDIG mSG to in" ascii //weight: 1
        $x_1_5 = "Lcom/benstokes/pathakschook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

