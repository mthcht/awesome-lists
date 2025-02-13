rule TrojanSpy_AndroidOS_BanBra_B_2147810009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/BanBra.B!MTB"
        threat_id = "2147810009"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "BanBra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Defensor ID-01" ascii //weight: 1
        $x_2_2 = "://empresasenegocios.online/remoteControl/" ascii //weight: 2
        $x_1_3 = "DataSnapshot" ascii //weight: 1
        $x_1_4 = "firebaseCmd" ascii //weight: 1
        $x_1_5 = "firebase/database/connection/idl/IPersistentConnectionImpl$1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

