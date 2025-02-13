rule TrojanSpy_AndroidOS_Knbot_A_2147754403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Knbot.A!MTB"
        threat_id = "2147754403"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Knbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "free.zwifipro.com/gate" ascii //weight: 1
        $x_1_2 = "pub.zwifi.pro" ascii //weight: 1
        $x_1_3 = "func] [msg] [recvPushMsg] [onReceive" ascii //weight: 1
        $x_1_4 = "eventBot" ascii //weight: 1
        $x_1_5 = "gate_cb8a5aea1ab302f0_c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Knbot_B_2147754533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Knbot.B!MTB"
        threat_id = "2147754533"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Knbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system/bin/screencap" ascii //weight: 1
        $x_1_2 = "SMS> N :" ascii //weight: 1
        $x_1_3 = "Lsystem/operating/dominance/proj" ascii //weight: 1
        $x_1_4 = "public//recoording.wav" ascii //weight: 1
        $x_1_5 = "Do I have root?" ascii //weight: 1
        $x_1_6 = "system/sd/temporary.txt" ascii //weight: 1
        $x_1_7 = "onOutgoingCallEnded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

