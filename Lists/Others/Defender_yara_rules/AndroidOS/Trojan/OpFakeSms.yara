rule Trojan_AndroidOS_OpFakeSms_A_2147652258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.A"
        threat_id = "2147652258"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sentSmsCount" ascii //weight: 1
        $x_1_2 = "updater3/OperaUpdaterActivity" ascii //weight: 1
        $x_1_3 = "SmsOperator.java" ascii //weight: 1
        $x_1_4 = "Exception !!!!!!!!!!!!!!!!!" ascii //weight: 1
        $x_1_5 = "raw/sms.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_A_2147652258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.A"
        threat_id = "2147652258"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 00 2b 00 [0-8] 6e 10 [0-12] 0c 00 [0-8] 11 00 [0-8] 22 01 2c 00 [0-8] 70 10 [0-12] 62 00 [0-10] 12 00 [0-8] 6e 10 ?? ?? 04 00 [0-8] 0a 02 [0-8] 34 20 [0-10] 6e 10 [0-12] 0c 00 [0-8] 62 01 [0-10] 6e 30 ?? ?? 41 00 [0-8] 28 [0-9] 22 02 23 00 [0-8] 6e 20 [0-12] 0a 03 [0-8] 70 20 ?? ?? 32 00 [0-8] 62 03 [0-10] 6e 20 [0-12] 0c 03 [0-8] 38 03 [0-10] 62 03 [0-10] 6e 20 ?? ?? 23 00 [0-8] 0c 02 [0-8] 6e 20 [0-12] d8 00 00 01 [0-8] 28 [0-9] 6e 20 ?? ?? 04 00 [0-8] 0a 02 [0-8] 6e 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_B_2147653510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.B"
        threat_id = "2147653510"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REQUEST_SUCCES" ascii //weight: 1
        $x_1_2 = "first_activity" ascii //weight: 1
        $x_1_3 = "succes.txt" ascii //weight: 1
        $x_1_4 = "SuccesActivity.java" ascii //weight: 1
        $x_1_5 = "isNeedSendSmsMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_B_2147653510_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.B"
        threat_id = "2147653510"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lerh8/nmm6/BService" ascii //weight: 1
        $x_1_2 = "Lnuu643/JJK73f/Njjkreh;" ascii //weight: 1
        $x_1_3 = "Ldsrhki/yjgfqjejkjh/nlrskgblc;" ascii //weight: 1
        $x_1_4 = "Lvbkoxh/cswnpr/cjbmtfwdy;" ascii //weight: 1
        $x_1_5 = "Lp34dc39fd/p1f4c00e5/p4015e9ce;" ascii //weight: 1
        $x_1_6 = "Lp97c9d58a/pd23b12ee/pbd044d03;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_C_2147655065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.C"
        threat_id = "2147655065"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://m-001.net/index.php" ascii //weight: 1
        $x_1_2 = "AlphaReceiver.java" ascii //weight: 1
        $x_1_3 = "Alpha sendRequest START" ascii //weight: 1
        $x_1_4 = "Y6Cg03N.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_E_2147662269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.E"
        threat_id = "2147662269"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "config.res" ascii //weight: 1
        $x_1_2 = "SMScol:" ascii //weight: 1
        $x_1_3 = "###LOG###" ascii //weight: 1
        $x_1_4 = "megafon" ascii //weight: 1
        $x_1_5 = "/setTask.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_OpFakeSms_A_2147827513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/OpFakeSms.A!MTB"
        threat_id = "2147827513"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "OpFakeSms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6auyfgk6olbxcs6olbxcs7kvnlefm7eojwwby6lybfox6lybfox7bogpacc7wytspon6pdmdta6pdmdta8puecocwi7lyapocw8khqoguvl8qucqxrbu6olbxcs6lybfox7poyhley6lybfox" ascii //weight: 1
        $x_1_2 = "7bogpacc6lynlnt7kvnlefm6rxmdda6pdmdta8puecocwi7gvbpxuc8vwaihouv6pdmdta6aosnff" ascii //weight: 1
        $x_1_3 = "vclcgkfg7kpkwqbf6jlfmdp7kpkwqbf" ascii //weight: 1
        $x_1_4 = "7kpkwqbf6auyfgk7qrexndu8seyatawn6olbxcs8ovipvtny8xahtxlxt6olbxcs8frhhqylm8rqlksuol7kheevwa7poyhley7kpkwqbf6olbxcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

