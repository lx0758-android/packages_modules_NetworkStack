/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.dhcp6;

import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_OPTION_LEN;

import android.net.MacAddress;
import android.util.Log;

import androidx.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;
import com.android.net.module.util.Struct;
import com.android.net.module.util.structs.IaNaOption;
import com.android.net.module.util.structs.IaAddressOption;
import com.android.net.module.util.structs.IaPdOption;
import com.android.net.module.util.structs.IaPrefixOption;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Defines basic data and operations needed to build and use packets for the
 * DHCPv6 protocol. Subclasses create the specific packets used at each
 * stage of the negotiation.
 *
 * @hide
 */
public class Dhcp6Packet {
    private static final String TAG = Dhcp6Packet.class.getSimpleName();
    /**
     * DHCPv6 Message Type.
     */
    public static final byte DHCP6_MESSAGE_TYPE_SOLICIT = 1;
    public static final byte DHCP6_MESSAGE_TYPE_ADVERTISE = 2;
    public static final byte DHCP6_MESSAGE_TYPE_REQUEST = 3;
    public static final byte DHCP6_MESSAGE_TYPE_CONFIRM = 4;
    public static final byte DHCP6_MESSAGE_TYPE_RENEW = 5;
    public static final byte DHCP6_MESSAGE_TYPE_REBIND = 6;
    public static final byte DHCP6_MESSAGE_TYPE_REPLY = 7;
    public static final byte DHCP6_MESSAGE_TYPE_RELEASE = 8;
    public static final byte DHCP6_MESSAGE_TYPE_DECLINE = 9;
    public static final byte DHCP6_MESSAGE_TYPE_RECONFIGURE = 10;
    public static final byte DHCP6_MESSAGE_TYPE_INFORMATION_REQUEST = 11;
    public static final byte DHCP6_MESSAGE_TYPE_RELAY_FORW = 12;
    public static final byte DHCP6_MESSAGE_TYPE_RELAY_REPL = 13;

    /**
     * DHCPv6 Optional Type: Client Identifier.
     * DHCPv6 message from client must have this option.
     */
    public static final byte DHCP6_CLIENT_IDENTIFIER = 1;
    @NonNull
    protected final byte[] mClientDuid;

    /**
     * DHCPv6 Optional Type: Server Identifier.
     */
    public static final byte DHCP6_SERVER_IDENTIFIER = 2;
    protected final byte[] mServerDuid;

    /**
     * DHCPv6 Optional Type: Option Request Option.
     */
    public static final byte DHCP6_OPTION_REQUEST_OPTION = 6;

    /**
     * DHCPv6 Optional Type: Elapsed time.
     * This time is expressed in hundredths of a second.
     */
    public static final byte DHCP6_ELAPSED_TIME = 8;
    protected final int mElapsedTime;

    /**
     * DHCPv6 Optional Type: Status Code.
     */
    public static final byte DHCP6_STATUS_CODE = 13;
    private static final byte MIN_STATUS_CODE_OPT_LEN = 6;
    protected short mStatusCode;

    public static final short STATUS_SUCCESS           = 0;
    public static final short STATUS_UNSPEC_FAIL       = 1;
    public static final short STATUS_NO_ADDRS_AVAIL    = 2;
    public static final short STATUS_NO_BINDING        = 3;
    public static final short STATUS_NOT_ONLINK        = 4;
    public static final short STATUS_USE_MULTICAST     = 5;
    public static final short STATUS_NO_PREFIX_AVAIL   = 6;

    /**
     * DHCPv6 zero-length Optional Type: Rapid Commit. Per RFC4039, both DHCPDISCOVER and DHCPACK
     * packet may include this option.
     */
    public static final byte DHCP6_RAPID_COMMIT = 14;
    public boolean mRapidCommit;

    /**
     * DHCPv6 Optional Type: IA_NA.
     */
    public static final byte DHCP6_IA_NA = 3;
    protected final byte[] mIaNa;
    protected NontemporaryAddresses mNontemporaryAddresses;

    /**
     * DHCPv6 Optional Type: IAADDR.
     */
    public static final byte DHCP6_IAADDR = 5;

    /**
     * DHCPv6 Optional Type: IA_PD.
     */
    public static final byte DHCP6_IA_PD = 25;
    protected final byte[] mIaPd;
    protected PrefixDelegation mPrefixDelegation;

    /**
     * DHCPv6 Optional Type: IA Prefix Option.
     */
    public static final byte DHCP6_IAPREFIX = 26;

    /**
     * DHCPv6 Optional Type: SOL_MAX_RT.
     */
    public static final byte DHCP6_SOL_MAX_RT = 82;
    private OptionalInt mSolMaxRt;

    /**
     * The transaction identifier used in this particular DHCPv6 negotiation
     */
    protected final int mTransId;

    /**
     * The unique identifier for IA_NA used in this particular DHCPv6 negotiation
     */
    protected int mIaIdForNa;
    /**
     * The unique identifier for IA_PD used in this particular DHCPv6 negotiation
     */
    protected int mIaIdForPd;

    // Per rfc8415#section-12, the IAID MUST be consistent across restarts.
    public static final int IAID_NA = 1;
    public static final int IAID_PD = 0; // Follow the value of IAID in the Android standard code

    Dhcp6Packet(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
            final byte[] serverDuid, final byte[] iana, final byte[] iapd) {
        mTransId = transId;
        mElapsedTime = elapsedTime;
        mClientDuid = clientDuid;
        mServerDuid = serverDuid;
        mIaNa = iana;
        mIaPd = iapd;
    }

    /**
     * Returns the transaction ID.
     */
    public int getTransactionId() {
        return mTransId;
    }

    /**
     * Returns decoded IA_NA options associated with IA_ID.
     */
    @VisibleForTesting
    public NontemporaryAddresses getNontemporaryAddresses() {
        return mNontemporaryAddresses;
    }

    /**
     * Returns decoded IA_PD options associated with IA_ID.
     */
    @VisibleForTesting
    public PrefixDelegation getPrefixDelegation() {
        return mPrefixDelegation;
    }

    /**
     * Returns IA_ID associated to IA_NA.
     */
    public int getIaIdForNa() {
        return mIaIdForNa;
    }

    /**
     * Returns IA_ID associated to IA_PD.
     */
    public int getIaIdForPd() {
        return mIaIdForPd;
    }

    /**
     * Returns the client's DUID.
     */
    @NonNull
    public byte[] getClientDuid() {
        return mClientDuid;
    }

    /**
     * Returns the server's DUID.
     */
    public byte[] getServerDuid() {
        return mServerDuid;
    }

    /**
     * Returns the SOL_MAX_RT option value in milliseconds.
     */
    public OptionalInt getSolMaxRtMs() {
        return mSolMaxRt;
    }

    /**
     * A class to take DHCPv6 IA_NA option allocated from server.
     * https://www.rfc-editor.org/rfc/rfc8415.html#section-21.4
     */
    public static class NontemporaryAddresses {
        public final int iaid;
        public final int t1;
        public final int t2;
        @NonNull
        public final List<IaAddressOption> iaos;

        @VisibleForTesting
        public NontemporaryAddresses(int iaid, int t1, int t2,
                @NonNull final List<IaAddressOption> iaos) {
            Objects.requireNonNull(iaos);
            this.iaid = iaid;
            this.t1 = t1;
            this.t2 = t2;
            this.iaos = iaos;
        }
        public boolean isValid() {
            if (iaid != IAID_NA) {
                Log.w(TAG, "IA_ID doesn't match, expected: " + IAID_NA + ", actual: " + iaid);
                return false;
            }
            if (t1 < 0 || t2 < 0) {
                Log.e(TAG, "IA_NA option with invalid T1 " + t1 + " or T2 " + t2);
                return false;
            }
            // Generally, t1 must be smaller or equal to t2 (except when t2 is 0).
            if (t2 != 0 && t1 > t2) {
                Log.e(TAG, "IA_NA option with T1 " + t1 + " greater than T2 " + t2);
                return false;
            }
            return true;
        }
        

        /**
         * Decode an IA_PD option from the byte buffer.
         */
        public static NontemporaryAddresses decode(@NonNull final ByteBuffer buffer)
                throws ParseException {
            try {
                final int iaid = buffer.getInt();
                final int t1 = buffer.getInt();
                final int t2 = buffer.getInt();
                final List<IaAddressOption> iaos = new ArrayList<IaAddressOption>();
                while (buffer.remaining() > 0) {
                    final int original = buffer.position();
                    final short optionType = buffer.getShort();
                    final int optionLen = buffer.getShort() & 0xFFFF;
                    switch (optionType) {
                        case DHCP6_IAADDR:
                            buffer.position(original);
                            final IaAddressOption ipo = Struct.parse(IaAddressOption.class, buffer);
                            Log.d(TAG, "IA Address Option: " + ipo);
                            iaos.add(ipo);
                            break;
                        default:
                            skipOption(buffer, optionLen);
                    }
                }
                return new NontemporaryAddresses(iaid, t1, t2, iaos);
            } catch (BufferUnderflowException e) {
                throw new ParseException(e.getMessage());
            }
        }

        /**
         * Build an IA_NA option from given specific parameters, including IA_ADDRESS options.
         */
        public ByteBuffer build() {
            return build(iaos);
        }

        /**
         * Build an IA_NA option from given specific parameters, including IA_ADDRESS options.
         */
        public ByteBuffer build(@NonNull final List<IaAddressOption> input) {
            final ByteBuffer iana = ByteBuffer.allocate(IaNaOption.LENGTH
                    + Struct.getSize(IaAddressOption.class) * input.size());
            iana.putInt(iaid);
            iana.putInt(t1);
            iana.putInt(t2);
            for (IaAddressOption ipo : input) {
                ipo.writeToByteBuffer(iana);
            }
            iana.flip();
            return iana;
        }

        public List<IaAddressOption> getValidIaAddresses() {
            final List<IaAddressOption> validIpos = new ArrayList<IaAddressOption>();
            for (IaAddressOption ipo : iaos) {
                if (!ipo.isValid()) continue;
                validIpos.add(ipo);
            }
            return validIpos;
        }

        @Override
        public String toString() {
            return String.format("Non-Temporary Addresses, iaid: %s, t1: %s, t2: %s,"
                    + " IA address options: %s", iaid, t1, t2, iaos);
        }

        /**
         * Compare the preferred lifetime in the IA address option list and return the minimum one.
         */
        public long getMinimalPreferredLifetime() {
            long min = Long.MAX_VALUE;
            for (IaAddressOption iao : iaos) {
                min = (iao.preferred != 0 && min > iao.preferred) ? iao.preferred : min;
            }
            return min;
        }

        /**
         * Compare the valid lifetime in the IA address optin list and return the minimum one.
         */
        public long getMinimalValidLifetime() {
            long min = Long.MAX_VALUE;
            for (IaAddressOption iao : iaos) {
                min = (iao.valid != 0 && min > iao.valid) ? iao.valid : min;
            }
            return min;
        }

        /**
         * Return IA address option list to be renewed/rebound.
         *
         * Per RFC8415#section-18.2.4, client must not include any addresses that it didn't obtain
         * from server or that are no longer valid (that have a valid lifetime of 0). Section-18.3.4
         * also mentions that server can inform client that it will not extend the address by setting
         * T1 and T2 to values equal to the valid lifetime, so in this case client has no point in
         * renewing as well.
         */
        public List<IaAddressOption> getRenewableIaAddresses() {
            final List<IaAddressOption> toBeRenewed = getValidIaAddresses();
            toBeRenewed.removeIf(iao -> iao.preferred == 0 && iao.valid == 0);
            toBeRenewed.removeIf(iao -> t1 == iao.valid && t2 == iao.valid);
            return toBeRenewed;
        }
    }

    /**
     * A class to take DHCPv6 IA_PD option allocated from server.
     * https://www.rfc-editor.org/rfc/rfc8415.html#section-21.21
     */
    public static class PrefixDelegation {
        public final int iaid;
        public final int t1;
        public final int t2;
        @NonNull
        public final List<IaPrefixOption> ipos;
        public final short statusCode;

        @VisibleForTesting
        public PrefixDelegation(int iaid, int t1, int t2,
                @NonNull final List<IaPrefixOption> ipos, short statusCode) {
            Objects.requireNonNull(ipos);
            this.iaid = iaid;
            this.t1 = t1;
            this.t2 = t2;
            this.ipos = ipos;
            this.statusCode = statusCode;
        }

        public PrefixDelegation(int iaid, int t1, int t2,
                @NonNull final List<IaPrefixOption> ipos) {
            this(iaid, t1, t2, ipos, STATUS_SUCCESS /* statusCode */);
        }

        /**
         * Check whether or not the IA_PD option in DHCPv6 message is valid.
         *
         * TODO: ensure that the prefix has a reasonable lifetime, and the timers aren't too short.
         */
        public boolean isValid() {
            if (iaid != IAID_PD) {
                Log.w(TAG, "IA_ID doesn't match, expected: " + IAID_PD + ", actual: " + iaid);
                return false;
            }
            if (t1 < 0 || t2 < 0) {
                Log.e(TAG, "IA_PD option with invalid T1 " + t1 + " or T2 " + t2);
                return false;
            }
            // Generally, t1 must be smaller or equal to t2 (except when t2 is 0).
            if (t2 != 0 && t1 > t2) {
                Log.e(TAG, "IA_PD option with T1 " + t1 + " greater than T2 " + t2);
                return false;
            }
            return true;
        }

        /**
         * Decode an IA_PD option from the byte buffer.
         */
        public static PrefixDelegation decode(@NonNull final ByteBuffer buffer)
                throws ParseException {
            try {
                final int iaid = buffer.getInt();
                final int t1 = buffer.getInt();
                final int t2 = buffer.getInt();
                final List<IaPrefixOption> ipos = new ArrayList<IaPrefixOption>();
                short statusCode = STATUS_SUCCESS;
                while (buffer.remaining() > 0) {
                    final int original = buffer.position();
                    final short optionType = buffer.getShort();
                    final int optionLen = buffer.getShort() & 0xFFFF;
                    switch (optionType) {
                        case DHCP6_IAPREFIX:
                            buffer.position(original);
                            final IaPrefixOption ipo = Struct.parse(IaPrefixOption.class, buffer);
                            Log.d(TAG, "IA Prefix Option: " + ipo);
                            ipos.add(ipo);
                            break;
                        case DHCP6_STATUS_CODE:
                            statusCode = buffer.getShort();
                            // Skip the status message if any.
                            if (optionLen > 2) {
                                skipOption(buffer, optionLen - 2);
                            }
                            break;
                        default:
                            skipOption(buffer, optionLen);
                    }
                }
                return new PrefixDelegation(iaid, t1, t2, ipos, statusCode);
            } catch (BufferUnderflowException e) {
                throw new ParseException(e.getMessage());
            }
        }

        /**
         * Build an IA_PD option from given specific parameters, including IA_PREFIX options.
         */
        public ByteBuffer build() {
            return build(ipos);
        }

        /**
         * Build an IA_PD option from given specific parameters, including IA_PREFIX options.
         *
         * Per RFC8415 section 21.13 if the Status Code option does not appear in a message in
         * which the option could appear, the status of the message is assumed to be Success. So
         * only put the Status Code option in IA_PD when the status code is not Success.
         */
        public ByteBuffer build(@NonNull final List<IaPrefixOption> input) {
            final ByteBuffer iapd = ByteBuffer.allocate(IaPdOption.LENGTH
                    + Struct.getSize(IaPrefixOption.class) * input.size()
                    + (statusCode != STATUS_SUCCESS ? MIN_STATUS_CODE_OPT_LEN : 0));
            iapd.putInt(iaid);
            iapd.putInt(t1);
            iapd.putInt(t2);
            for (IaPrefixOption ipo : input) {
                ipo.writeToByteBuffer(iapd);
            }
            if (statusCode != STATUS_SUCCESS) {
                iapd.putShort(DHCP6_STATUS_CODE);
                iapd.putShort((short) 2);
                iapd.putShort(statusCode);
            }
            iapd.flip();
            return iapd;
        }

        /**
         * Return valid IA prefix options to be used and extended in the Reply message. It may
         * return empty list if there isn't any valid IA prefix option in the Reply message.
         *
         * TODO: ensure that the prefix has a reasonable lifetime, and the timers aren't too short.
         * and handle status code such as NoPrefixAvail.
         */
        public List<IaPrefixOption> getValidIaPrefixes() {
            final List<IaPrefixOption> validIpos = new ArrayList<IaPrefixOption>();
            for (IaPrefixOption ipo : ipos) {
                if (!ipo.isValid()) continue;
                validIpos.add(ipo);
            }
            return validIpos;
        }

        @Override
        public String toString() {
            return String.format("Prefix Delegation, iaid: %s, t1: %s, t2: %s, status code: %s,"
                    + " IA prefix options: %s", iaid, t1, t2, statusCodeToString(statusCode), ipos);
        }

        /**
         * Compare the preferred lifetime in the IA prefix optin list and return the minimum one.
         */
        public long getMinimalPreferredLifetime() {
            long min = Long.MAX_VALUE;
            for (IaPrefixOption ipo : ipos) {
                min = (ipo.preferred != 0 && min > ipo.preferred) ? ipo.preferred : min;
            }
            return min;
        }

        /**
         * Compare the valid lifetime in the IA prefix optin list and return the minimum one.
         */
        public long getMinimalValidLifetime() {
            long min = Long.MAX_VALUE;
            for (IaPrefixOption ipo : ipos) {
                min = (ipo.valid != 0 && min > ipo.valid) ? ipo.valid : min;
            }
            return min;
        }

        /**
         * Return IA prefix option list to be renewed/rebound.
         *
         * Per RFC8415#section-18.2.4, client must not include any prefixes that it didn't obtain
         * from server or that are no longer valid (that have a valid lifetime of 0). Section-18.3.4
         * also mentions that server can inform client that it will not extend the prefix by setting
         * T1 and T2 to values equal to the valid lifetime, so in this case client has no point in
         * renewing as well.
         */
        public List<IaPrefixOption> getRenewableIaPrefixes() {
            final List<IaPrefixOption> toBeRenewed = getValidIaPrefixes();
            toBeRenewed.removeIf(ipo -> ipo.preferred == 0 && ipo.valid == 0);
            toBeRenewed.removeIf(ipo -> t1 == ipo.valid && t2 == ipo.valid);
            return toBeRenewed;
        }
    }

    /**
     * DHCPv6 packet parsing exception.
     */
    public static class ParseException extends Exception {
        ParseException(String msg) {
            super(msg);
        }
    }

    private static String statusCodeToString(short statusCode) {
        switch (statusCode) {
            case STATUS_SUCCESS:
                return "Success";
            case STATUS_UNSPEC_FAIL:
                return "UnspecFail";
            case STATUS_NO_ADDRS_AVAIL:
                return "NoAddrsAvail";
            case STATUS_NO_BINDING:
                return "NoBinding";
            case STATUS_NOT_ONLINK:
                return "NotOnLink";
            case STATUS_USE_MULTICAST:
                return "UseMulticast";
            case STATUS_NO_PREFIX_AVAIL:
                return "NoPrefixAvail";
            default:
                return "Unknown";
        }
    }

    private static void skipOption(@NonNull final ByteBuffer packet, int optionLen)
            throws BufferUnderflowException {
        for (int i = 0; i < optionLen; i++) {
            packet.get();
        }
    }

    /**
     * Creates a concrete Dhcp6Packet from the supplied ByteBuffer.
     *
     * The buffer only starts with a UDP encapsulation (i.e. DHCPv6 message). A subset of the
     * optional parameters are parsed and are stored in object fields. Client/Server message
     * format:
     *
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    msg-type   |               transaction-id                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * .                            options                            .
     * .                 (variable number and length)                  .
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    private static Dhcp6Packet decode(@NonNull final ByteBuffer packet) throws ParseException {
        int elapsedTime = 0;
        byte[] iana = null;
        byte[] iapd = null;
        byte[] serverDuid = null;
        byte[] clientDuid = null;
        short statusCode = STATUS_SUCCESS;
        boolean rapidCommit = false;
        int solMaxRt = 0;
        NontemporaryAddresses na = null;
        PrefixDelegation pd = null;

        packet.order(ByteOrder.BIG_ENDIAN);

        // DHCPv6 message contents.
        final int msgTypeAndTransId = packet.getInt();
        final byte messageType = (byte) (msgTypeAndTransId >> 24);
        final int transId = msgTypeAndTransId & 0xffffff;

        /**
         * Parse DHCPv6 options, option format:
         *
         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |          option-code          |           option-len          |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                          option-data                          |
         * |                      (option-len octets)                      |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        while (packet.hasRemaining()) {
            try {
                final short optionType = packet.getShort();
                final int optionLen = packet.getShort() & 0xFFFF;
                int expectedLen = 0;

                switch(optionType) {
                    case DHCP6_SERVER_IDENTIFIER:
                        expectedLen = optionLen;
                        final byte[] sduid = new byte[expectedLen];
                        packet.get(sduid, 0 /* offset */, expectedLen);
                        serverDuid = sduid;
                        break;
                    case DHCP6_CLIENT_IDENTIFIER:
                        expectedLen = optionLen;
                        final byte[] cduid = new byte[expectedLen];
                        packet.get(cduid, 0 /* offset */, expectedLen);
                        clientDuid = cduid;
                        break;
                    case DHCP6_IA_NA:
                        expectedLen = optionLen;
                        final byte[] iaNaBytes = new byte[expectedLen];
                        packet.get(iaNaBytes, 0 /* offset */, expectedLen);
                        iana = iaNaBytes;
                        na = NontemporaryAddresses.decode(ByteBuffer.wrap(iana));
                        break;
                    case DHCP6_IA_PD:
                        expectedLen = optionLen;
                        final byte[] iaPdBytes = new byte[expectedLen];
                        packet.get(iaPdBytes, 0 /* offset */, expectedLen);
                        iapd = iaPdBytes;
                        pd = PrefixDelegation.decode(ByteBuffer.wrap(iapd));
                        break;
                    case DHCP6_RAPID_COMMIT:
                        expectedLen = 0;
                        rapidCommit = true;
                        break;
                    case DHCP6_ELAPSED_TIME:
                        expectedLen = 2;
                        elapsedTime = (int) (packet.getShort() & 0xFFFF);
                        break;
                    case DHCP6_STATUS_CODE:
                        expectedLen = optionLen;
                        statusCode = packet.getShort();
                        // Skip the status message (if any), which is a UTF-8 encoded text string
                        // suitable for display to the end user, but is not useful for Dhcp6Client
                        // to decide how to properly handle the status code.
                        if (optionLen - 2 > 0) {
                            skipOption(packet, optionLen - 2);
                        }
                        break;
                    case DHCP6_SOL_MAX_RT:
                        expectedLen = 4;
                        solMaxRt = packet.getInt();
                        break;
                    default:
                        expectedLen = optionLen;
                        // BufferUnderflowException will be thrown if option is truncated.
                        skipOption(packet, optionLen);
                        break;
                }
                if (expectedLen != optionLen) {
                    throw new ParseException(
                            "Invalid length " + optionLen + " for option " + optionType
                                    + ", expected " + expectedLen);
                }
            } catch (BufferUnderflowException e) {
                throw new ParseException(e.getMessage());
            }
        }

        Dhcp6Packet newPacket;

        switch(messageType) {
            case DHCP6_MESSAGE_TYPE_SOLICIT:
                newPacket = new Dhcp6SolicitPacket(transId, elapsedTime, clientDuid, iana, iapd, rapidCommit);
                break;
            case DHCP6_MESSAGE_TYPE_ADVERTISE:
                newPacket = new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iana, iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REQUEST:
                newPacket = new Dhcp6RequestPacket(transId, elapsedTime, clientDuid, serverDuid, iana, iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REPLY:
                newPacket = new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iana, iapd, rapidCommit);
                break;
            case DHCP6_MESSAGE_TYPE_RENEW:
                newPacket = new Dhcp6RenewPacket(transId, elapsedTime, clientDuid, serverDuid, iana, iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REBIND:
                newPacket = new Dhcp6RebindPacket(transId, elapsedTime, clientDuid, iana, iapd);
                break;
            default:
                throw new ParseException("Unimplemented DHCP6 message type %d" + messageType);
        }

        if (na != null) {
            newPacket.mIaIdForNa = na.iaid;
            newPacket.mNontemporaryAddresses = na;
        }
        if (pd != null) {
            newPacket.mIaIdForPd = pd.iaid;
            newPacket.mPrefixDelegation = pd;
        }
        newPacket.mStatusCode = statusCode;
        newPacket.mRapidCommit = rapidCommit;
        newPacket.mSolMaxRt =
                (solMaxRt >= 60 && solMaxRt <= 86400)
                        ? OptionalInt.of(solMaxRt * 1000)
                        : OptionalInt.empty();

        return newPacket;
    }

    /**
     * Parse a packet from an array of bytes, stopping at the given length.
     */
    public static Dhcp6Packet decode(@NonNull final byte[] packet, int length)
            throws ParseException {
        final ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);
        return decode(buffer);
    }

    /**
     * Follow RFC8415 section 18.2.9 and 18.2.10 to check if the received DHCPv6 message is valid.
     */
    public boolean isValid(int transId, @NonNull final byte[] clientDuid) {
        if (mClientDuid == null) {
            Log.e(TAG, "DHCPv6 message without Client DUID option");
            return false;
        }
        if (!Arrays.equals(mClientDuid, clientDuid)) {
            Log.e(TAG, "Unexpected client DUID " + HexDump.toHexString(mClientDuid)
                    + ", expected " + HexDump.toHexString(clientDuid));
            return false;
        }
        if (mTransId != transId) {
            Log.e(TAG, "Unexpected transaction ID " + mTransId + ", expected " + transId);
            return false;
        }
        if (mNontemporaryAddresses == null && mPrefixDelegation == null) {
            Log.e(TAG, "DHCPv6 message without IA_NA or IA_PD option, ignoring");
            return false;
        }
        if (!mNontemporaryAddresses.isValid() && !mPrefixDelegation.isValid()) {
            Log.e(TAG, "DHCPv6 message takes invalid IA_NA and IA_PD option, ignoring");
            return false;
        }
        //TODO: check if the status code is success or not.
        return true;
    }

    /**
     * Returns the client DUID, follows RFC 8415 and creates a client DUID
     * based on the link-layer address(DUID-LL).
     *
     * TODO: use Struct to build and parse DUID.
     *
     * 0                   1                   2                   3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         DUID-Type (3)         |    hardware type (16 bits)    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * .                                                               .
     * .             link-layer address (variable length)              .
     * .                                                               .
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    public static byte[] createClientDuid(@NonNull final MacAddress macAddress) {
        final byte[] duid = new byte[10];
        // type: Link-layer address(3)
        duid[0] = (byte) 0x00;
        duid[1] = (byte) 0x03;
        // hardware type: Ethernet(1)
        duid[2] = (byte) 0x00;
        duid[3] = (byte) 0x01;
        System.arraycopy(macAddress.toByteArray() /* src */, 0 /* srcPos */, duid /* dest */,
                4 /* destPos */, 6 /* length */);
        return duid;
    }

    /**
     * Adds an optional parameter containing an array of bytes.
     */
    protected static void addTlv(ByteBuffer buf, short type, @NonNull byte[] payload) {
        if (payload.length > DHCP_MAX_OPTION_LEN) {
            throw new IllegalArgumentException("DHCP option too long: "
                    + payload.length + " vs. " + DHCP_MAX_OPTION_LEN);
        }
        buf.putShort(type);
        buf.putShort((short) payload.length);
        buf.put(payload);
    }

    /**
     * Adds an optional parameter containing a short integer.
     */
    protected static void addTlv(ByteBuffer buf, short type, short value) {
        buf.putShort(type);
        buf.putShort((short) 2);
        buf.putShort(value);
    }

    /**
     * Adds an optional parameter containing zero-length value.
     */
    protected static void addTlv(ByteBuffer buf, short type) {
        buf.putShort(type);
        buf.putShort((short) 0);
    }

    /**
     * Builds a DHCPv6 SOLICIT packet from the required specified parameters.
     */
    public static ByteBuffer buildSolicitPacket(int transId, long millisecs,
            final byte[] iana, final byte[] iapd, @NonNull final byte[] clientDuid, boolean rapidCommit) {
        final Dhcp6SolicitPacket pkt =
                new Dhcp6SolicitPacket(transId, (int) (millisecs / 10) /* elapsed time */,
                        clientDuid, iana, iapd, rapidCommit);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 ADVERTISE packet from the required specified parameters.
     */
    public static ByteBuffer buildAdvertisePacket(int transId, final byte[] iana, final byte[] iapd,
            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid) {
        final Dhcp6AdvertisePacket pkt =
                new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iana, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REPLY packet from the required specified parameters.
     */
    public static ByteBuffer buildReplyPacket(int transId, final byte[] iana, final byte[] iapd,
            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid,
            boolean rapidCommit) {
        final Dhcp6ReplyPacket pkt =
                new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iana, iapd, rapidCommit);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REQUEST packet from the required specified parameters.
     */
    public static ByteBuffer buildRequestPacket(int transId, long millisecs,
            final byte[] iana, final byte[] iapd, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid) {
        final Dhcp6RequestPacket pkt =
                new Dhcp6RequestPacket(transId, (int) (millisecs / 10) /* elapsed time */,
                        clientDuid, serverDuid, iana, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 RENEW packet from the required specified parameters.
     */
    public static ByteBuffer buildRenewPacket(int transId, long millisecs,
            final byte[] iana, final byte[] iapd, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid) {
        final Dhcp6RenewPacket pkt =
                new Dhcp6RenewPacket(transId, (int) (millisecs / 10) /* elapsed time */, clientDuid,
                        serverDuid, iana, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REBIND packet from the required specified parameters.
     */
    public static ByteBuffer buildRebindPacket(int transId, long millisecs,
            final byte[] iana, final byte[] iapd, @NonNull final byte[] clientDuid) {
        final Dhcp6RebindPacket pkt = new Dhcp6RebindPacket(transId,
                (int) (millisecs / 10) /* elapsed time */, clientDuid, iana, iapd);
        return pkt.buildPacket();
    }
}
