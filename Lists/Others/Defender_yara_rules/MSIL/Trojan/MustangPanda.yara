rule Trojan_MSIL_MustangPanda_AM_2147982402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MustangPanda.AM!MTB"
        threat_id = "2147982402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PDFgear" ascii //weight: 1
        $x_1_2 = "PDFgear Common Library" ascii //weight: 1
        $x_1_3 = "PDFgear_DeviceSync_Mutex" ascii //weight: 1
        $x_1_4 = "PDFgear DeviceSync" ascii //weight: 1
        $x_1_5 = "AesGcmCodec" ascii //weight: 1
        $x_1_6 = "BeCtrl.Config" ascii //weight: 1
        $x_1_7 = "BeCtrl.Logging" ascii //weight: 1
        $x_1_8 = "BeCtrl.Business.Cmd" ascii //weight: 1
        $x_1_9 = "BeCtrl.Business.Upload" ascii //weight: 1
        $x_1_10 = "[BeCtrl] fingerprint" ascii //weight: 1
        $x_1_11 = "BeCtrl.FileLogSink" ascii //weight: 1
        $x_1_12 = "LoginCodec only accepts kB2C_Login frames" ascii //weight: 1
        $x_1_13 = "Login frames must be encoded via LoginCodec.EncodeLogin" ascii //weight: 1
        $x_1_14 = "Login frames must be decoded via LoginCodec.DecodeLogin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

