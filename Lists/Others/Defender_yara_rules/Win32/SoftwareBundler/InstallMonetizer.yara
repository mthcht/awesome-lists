rule SoftwareBundler_Win32_InstallMonetizer_199745_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/InstallMonetizer"
        threat_id = "199745"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallMonetizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mail@gutscheinrausch.de.xpi" ascii //weight: 1
        $x_1_2 = "InstallManager Setup" ascii //weight: 1
        $x_1_3 = "s=''; a=r8; b=r7; #{b-->0,s=s+hex[a/16%16]+hex[a%16]+#[b>0,'-','']; a=a/256;}; r9=s;" ascii //weight: 1
        $x_1_4 = "&status=13&offid=2&log=" ascii //weight: 1
        $x_1_5 = "installmonetizer.com" ascii //weight: 1
        $x_32_6 = {2f 49 4d 5f [0-3] 61 70 70 69 6e 74 65 72 61 63 74 [0-3] 2e 70 68 70}  //weight: 32, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_32_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_InstallMonetizer_199745_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/InstallMonetizer"
        threat_id = "199745"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallMonetizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\OfferScreen_" ascii //weight: 1
        $x_1_2 = "\\Offer1.zip" ascii //weight: 1
        $x_1_3 = "&BundleVersionID=" ascii //weight: 1
        $x_1_4 = "&mode=checker&pubid=" ascii //weight: 1
        $x_1_5 = "Did not get first call response!! Quitting exe" ascii //weight: 1
        $x_1_6 = "Downloading One offer zip file" ascii //weight: 1
        $x_1_7 = "Offer3AdvInfoURL" ascii //weight: 1
        $x_1_8 = "M0L3Z5S0G1ME" ascii //weight: 1
        $x_50_9 = {2f 46 43 4c 5f 43 6f 5f [0-7] 72 65 6d 6f 74 65 [0-7] 2e 70 68 70}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_InstallMonetizer_199745_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/InstallMonetizer"
        threat_id = "199745"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallMonetizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\OfferScreen_" ascii //weight: 1
        $x_1_2 = "\\Offer1.zip" ascii //weight: 1
        $x_1_3 = "s=''; a=r8; b=r7; #{b-->0,s=s+hex[a/16%16]+hex[a%16]+#[b>0,'-','']; a=a/256;}; r9=s;" ascii //weight: 1
        $x_1_4 = "InstallManager Setup" ascii //weight: 1
        $x_1_5 = "N0K3Y5T0F1ND" ascii //weight: 1
        $x_1_6 = "&type=stub&mode=installer&advDetails=" ascii //weight: 1
        $x_1_7 = "&offid=1&status=53" ascii //weight: 1
        $x_32_8 = {2f 66 69 72 73 74 5f 63 61 6c 6c 5f [0-7] 2e 70 68 70}  //weight: 32, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_32_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_InstallMonetizer_199745_3
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/InstallMonetizer"
        threat_id = "199745"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallMonetizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "from=nsis&type=stub&itemid=" ascii //weight: 1
        $x_1_2 = {43 42 31 53 74 61 74 65 00 43 42 32 53 74 61 74 65}  //weight: 1, accuracy: High
        $x_1_3 = {51 75 69 63 6b 49 6e 73 74 61 6c 6c 00 4d 75 6c 74 69 4f 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "M0L3Z5S0G1ME" ascii //weight: 1
        $x_1_5 = "&type=stub&mode=installer&advDetails=" ascii //weight: 1
        $x_1_6 = "s=''; a=r8; b=r7; #{b-->0,s=s+hex[a/16%16]+hex[a%16]+#[b>0,'-','']; a=a/256;}; r9=s;" ascii //weight: 1
        $x_32_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 05 00 05 00 2e 75 73 [0-2] 02 00 [0-19] 2e 70 68 70}  //weight: 32, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_32_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_InstallMonetizer_199745_4
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/InstallMonetizer"
        threat_id = "199745"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "InstallMonetizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\OfferScreen_" ascii //weight: 1
        $x_1_2 = "\\Offer1.zip" ascii //weight: 1
        $x_1_3 = "&BundleVersionID=" ascii //weight: 1
        $x_1_4 = "&mode=checker&pubid=" ascii //weight: 1
        $x_1_5 = "&offid=1&status=53" ascii //weight: 1
        $x_1_6 = "M0L3Z5S0G1ME" ascii //weight: 1
        $x_1_7 = "N0K3Y5T0F1ND" ascii //weight: 1
        $x_1_8 = "www.installmonetizer.com" ascii //weight: 1
        $x_1_9 = "InstallManager Setup" ascii //weight: 1
        $n_100_10 = {38 30 30 35 00 37 33 30 39}  //weight: -100, accuracy: High
        $x_32_11 = {2f 46 43 4c 5f 43 6f 5f 55 6e 71 5f 65 74 6f 6d 65 72 [0-3] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_12 = {2f 46 43 4c 5f 43 6f 5f 55 6e 71 5f 77 65 65 64 65 [0-3] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_13 = {2f 46 43 4c 5f 43 6f 5f 4e 6f 61 65 72 65 72 5f 75 74 61 73 72 [0-3] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_14 = {2f 46 43 4c 5f 43 6f 5f [0-8] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_15 = {2f 46 43 4c 5f [0-15] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_16 = {2f 4c 43 46 5f 4f 63 5f 51 6e 75 5f 65 74 6f 6d 65 72 [0-3] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_17 = {2f 66 69 72 73 74 5f 63 61 6c 6c 5f [0-7] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_18 = {2f 43 46 4c 5f 57 69 74 68 5f [0-5] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_19 = "/Mla_bcdefr.php" ascii //weight: 32
        $x_32_20 = "/pichu_kok.php" ascii //weight: 32
        $x_32_21 = "www.fcesneim.us" ascii //weight: 32
        $x_32_22 = "www.fcimewns.us" ascii //weight: 32
        $x_32_23 = "www.fcmumovi.us" ascii //weight: 32
        $x_32_24 = "www.ntkemu.us" ascii //weight: 32
        $x_32_25 = "/swaya_var_pr.php" ascii //weight: 32
        $x_32_26 = "www.exprjdmn.us" ascii //weight: 32
        $x_32_27 = "/edi_pivadi_design.php" ascii //weight: 32
        $x_32_28 = "/ga_pdm_mnm.php" ascii //weight: 32
        $x_32_29 = {77 77 77 2e 66 63 06 00 2e 75 73}  //weight: 32, accuracy: Low
        $x_32_30 = {77 77 77 2e 66 63 03 00 05 00 2e 75 73 2f 03 00 [0-18] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_31 = {68 74 74 70 3a 2f 2f 77 77 77 2e 05 00 10 00 2e 75 73 2f 02 00 [0-19] 2e 70 68 70}  //weight: 32, accuracy: Low
        $x_32_32 = "www.yiserwlen.com" ascii //weight: 32
        $x_32_33 = "gd_bnk.php" ascii //weight: 32
        $x_32_34 = "www.vlanmjer.com" ascii //weight: 32
        $x_32_35 = "boardban.php" ascii //weight: 32
        $x_32_36 = "www.pzlersekr.com" ascii //weight: 32
        $x_32_37 = "/reflanker_fk.php" ascii //weight: 32
        $x_32_38 = "www.pelrsoher.com" ascii //weight: 32
        $x_32_39 = "/pc_vldar.php" ascii //weight: 32
        $x_32_40 = "www.welnrehis.com" ascii //weight: 32
        $x_32_41 = "/chnl_mnt.php" ascii //weight: 32
        $x_32_42 = "www.qulmrajes.com" ascii //weight: 32
        $x_32_43 = "/mrugan_jade.php" ascii //weight: 32
        $x_32_44 = "www.liramklut.com" ascii //weight: 32
        $x_32_45 = "/kika_rlsd.php" ascii //weight: 32
        $x_32_46 = "www.mopuvrzac.com" ascii //weight: 32
        $x_32_47 = "/pre_sgs.php" ascii //weight: 32
        $x_32_48 = "www.kelitbwop.com" ascii //weight: 32
        $x_32_49 = "/nasged_won.php" ascii //weight: 32
        $x_32_50 = "www.poscivner.com" ascii //weight: 32
        $x_32_51 = "/chlk_chnt.php" ascii //weight: 32
        $x_32_52 = "www.vetqalger.com" ascii //weight: 32
        $x_32_53 = "/sdgl_sdhr.php" ascii //weight: 32
        $x_32_54 = "www.aerwanyem.com" ascii //weight: 32
        $x_32_55 = "www.mivqutper.com" ascii //weight: 32
        $x_32_56 = "www.barkezyid.com" ascii //weight: 32
        $x_32_57 = "www.vuwpibfam.com" ascii //weight: 32
        $x_32_58 = "www.bavqonciz.com/krk_rp.php" ascii //weight: 32
        $x_32_59 = "www.bavqonciz.com/md_pl_wrp.php" ascii //weight: 32
        $n_100_60 = {39 38 00 31 31 36 31 35}  //weight: -100, accuracy: High
        $x_32_61 = "www.wuzjilrag.com/pts_prksh.php" ascii //weight: 32
        $x_32_62 = "www.wuzjilrag.com/md_pl_wrp.php" ascii //weight: 32
        $x_32_63 = "www.bifparvey.com/pts_prksh.php" ascii //weight: 32
        $x_32_64 = "www.kazrovsil.com" ascii //weight: 32
        $x_32_65 = "/pts_prksh.php" ascii //weight: 32
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_32_*))) or
            (all of ($x*))
        )
}

