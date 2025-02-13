rule TrojanSpy_AndroidOS_Micropsia_A_2147795715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Micropsia.A!MTB"
        threat_id = "2147795715"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Micropsia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onPostExecute: delete apk result" ascii //weight: 1
        $x_1_2 = "Apk Downloaded ?" ascii //weight: 1
        $x_1_3 = "/android/sys/contacts" ascii //weight: 1
        $x_1_4 = "rose-sturat.info@domains" ascii //weight: 1
        $x_1_5 = "sms_recording" ascii //weight: 1
        $x_1_6 = "call_recording" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

