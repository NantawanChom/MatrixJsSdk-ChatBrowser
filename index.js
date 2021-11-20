const BASE_URL = 'https://matrix.org';

const ROOM_CRYPTO_CONFIG = { algorithm: 'm.megolm.v1.aes-sha2' };
// Database
let opts = { indexedDB: window.indexedDB, localStorage: window.localStorage };
let store = new matrixcs.IndexedDBStore(opts);
// client info session
let client = null;
let user_id = "";
let access_token = "";
let home_server = "";
let device_id = "";
let display_name = "";
// logout session
let logoutBTN = document.getElementById('logoutbtn');

// login session
let username = document.getElementById('login_username');
let password = document.getElementById('login_password');
let tokenLoginText = document.getElementById('tokenLogin');
let Loginbtn = document.getElementById('loginbtn');
let deviceLoginText = document.getElementById('deviceLogin');

// register session

let regis_username = document.getElementById('regis_username');
let regis_password = document.getElementById('regis_password');
let Registerbtn = document.getElementById('Registerbtn');
let register_guestbtn = document.getElementById('register_guestbtn');

// generate key backup
let ssss_key = document.getElementById('ssss_key');
let encodedPrivateKey_text = document.getElementById('encodedPrivateKey_text');
let create_ssss_key_btn = document.getElementById("create_ssss_key");
let randomKeybtn = document.getElementById('randomKeybtn');
let copyGenKeybtn = document.getElementById('copyGenKeybtn');

// verified login security key
let verifiyKeybtn = document.getElementById('verifiyKeybtn');
let passphrase_text = document.getElementById('secure_phrase');
let secure_key_text = document.getElementById('secure_key');
let secure_key_file = document.getElementById('secure_key_file');

// verified another device session
let VerifiedBtn = document.getElementById('VerifiedBtn');

// get all room of user
let GetAllRoombtn = document.getElementById('GetAllRoombtn');

// create room
let RoomAliasName = document.getElementById('room_alias_name');
let RoomName = document.getElementById('room_name');
let RoomTopic = document.getElementById('topic_room');
let showRoomCreateID = document.getElementById('showRoomCreateID');
let showRoomAlias = document.getElementById('showRoomAlias');
let createRoombtn = document.getElementById('createRoombtn');

// delete or leave room
let RoomIDtoDeltxt = document.getElementById('RoomIDtoDel');
let delRoombtn = document.getElementById('del_room');
let Leavebtn = document.getElementById('leave_roombtn');

// chat in room session
let ActiveRoom = "";
let RoomIDtoChat = document.getElementById('roomIDtoChat');
let messageToSent = document.getElementById('messageToSent');
let StartChatbtn = document.getElementById('StartChatbtn');
let sentMessagebtn = document.getElementById('sentMessage');

// ==Implement SSSS (Secure Secret Storage and Sharing)==
let zerosalt = new Uint8Array(32);
let ZERO_STR = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
let passphrase = "";
let secure_key = "";

let passphrase_legth = 45; // at least 256 bits

function makeRandomKey() {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    var charactersLength = characters.length;
    for (var i = 0; i < passphrase_legth; i++) {
        result += characters.charAt(Math.floor(Math.random() *
            charactersLength));
    }
    return result;
}

function generateRandomKeyUser() {
    var result = makeRandomKey();

    ssss_key.value = result;
}

function copyKeyUser() {
    var copyText = document.getElementById("ssss_key");
    /* Select the text field */
    copyText.select();
    copyText.setSelectionRange(0, 99999); /* For mobile devices */

    /* Copy the text inside the text field */
    navigator.clipboard.writeText(copyText.value);

}

function encodeBase64(uint8Array) {
    return buffer.Buffer.from(uint8Array).toString("base64");
}
function decodeBase64(base64) {
    return buffer.Buffer.from(base64, "base64");
}

async function getSecretStorageKey({ keys }, name) {
    console.log(keys)
    for (const [keyName, keyInfo] of Object.entries(keys)) {
        if (keyInfo['algorithm'] == 'm.secret_storage.v1.aes-hmac-sha2') {
            if ((typeof keyInfo['mac'] == "string") && (typeof keyInfo['iv'] == 'string')) {
                const key = await deriveKey(passphrase, keyInfo.passphrase.salt, keyInfo.passphrase.iterations);
                var { mac } = await encryptAES(ZERO_STR, key, '', keyInfo['iv']);
                if (keyInfo.mac.replace(/=+$/g, '') === mac.replace(/=+$/g, '')) {
                    return [keyName, key];
                }
            } else {
                // no real information about the key, assume it is valid
                return true;
            }
        } else {
            throw 'Unknown Algorithm';
        }
    }
}

async function encryptAES(data, key, name, ivStr) {
    const subtleCrypto = window.crypto.subtle;
    let iv;
    if (ivStr) {
        iv = decodeBase64(ivStr);
    }
    else {
        iv = new Uint8Array(16);
        window.crypto.getRandomValues(iv);
    }
    // clear bit 63 of the IV to stop us hitting the 64-bit counter boundary
    // (which would mean we wouldn't be able to decrypt on Android). The loss
    // of a single bit of iv is a price we have to pay.
    iv[8] &= 0x7f;
    const [aesKey, hmacKey] = await deriveKeysBrowser(key, name);
    const encodedData = new TextEncoder().encode(data);
    const ciphertext = await subtleCrypto.encrypt({
        name: "AES-CTR",
        counter: iv,
        length: 64,
    }, aesKey, encodedData);
    const hmac = await subtleCrypto.sign('HMAC', hmacKey, ciphertext);
    return {
        iv: encodeBase64(iv),
        ciphertext: encodeBase64(ciphertext),
        mac: encodeBase64(hmac),
    };
}

async function deriveKey(password, salt, iterations, numBits = 256) {
    const subtleCrypto = window.crypto.subtle;
    const TextEncoder = window.TextEncoder;
    if (!subtleCrypto || !TextEncoder) {
        // TODO: Implement this for node
        throw new Error("Password-based backup is not avaiable on this platform");
    }
    const key = await subtleCrypto.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const keybits = await subtleCrypto.deriveBits({
        name: 'PBKDF2',
        salt: new TextEncoder().encode(salt),
        iterations: iterations,
        hash: 'SHA-512',
    }, key, numBits);
    return new Uint8Array(keybits);
}

async function deriveKeysBrowser(key, name) {
    const subtleCrypto = window.crypto.subtle;
    const hkdfkey = await subtleCrypto.importKey('raw', key, "HKDF", false, ["deriveBits"]);
    const keybits = await subtleCrypto.deriveBits({
        name: "HKDF",
        salt: zerosalt,
        info: (new TextEncoder().encode(name)),
        hash: "SHA-256",
    }, hkdfkey, 512);
    const aesKey = keybits.slice(0, 32);
    const hmacKey = keybits.slice(32);
    const aesProm = subtleCrypto.importKey('raw', aesKey, { name: 'AES-CTR' }, false, ['encrypt', 'decrypt']);
    const hmacProm = subtleCrypto.importKey('raw', hmacKey, {
        name: 'HMAC',
        hash: { name: 'SHA-256' },
    }, false, ['sign', 'verify']);
    return await Promise.all([aesProm, hmacProm]);
}

const cryptoCallbacks = {
    getSecretStorageKey: getSecretStorageKey,
    async getDehydrationKey() {
        return passphrase;
    },
    async generateDehydrationKey() {
        return { key: passphrase };
    }
};

// ==End implement SSSS==

const LoginUser = async () => {
    var usernameText = username.value;
    var passwordText = password.value;

    if (usernameText == '' || passwordText == '') {
        console.log("username or password invalid..")
        return
    }

    const loginClient = matrixcs.createClient(BASE_URL);

    const userLoginResult = await loginClient.loginWithPassword(
        usernameText, passwordText
    )

    // update user info when login
    user_id = userLoginResult.user_id;
    access_token = userLoginResult.access_token;
    home_server = userLoginResult.home_server;
    tokenLoginText.value = userLoginResult.access_token;

    await store.startup(); // load from indexed db

    client = matrixcs.createClient({
        baseUrl: BASE_URL,
        userId: user_id,
        accessToken: access_token,
        deviceId: userLoginResult.device_id,
        store: store,
        sessionStore: new matrixcs.WebStorageSessionStore(window.localStorage),
        cryptoStore: new matrixcs.MemoryCryptoStore(),
        cryptoCallbacks: cryptoCallbacks,
        verificationMethods: ["m.sas.v1", "m.qr_code.show.v1", "m.reciprocate.v1", "m.qr_code.scan.v1"]
    });
    device_id = client.deviceId;
    deviceLoginText.value = device_id;

    client.getProfileInfo(user_id, 'displayname').then((res) => {
        const { displayname } = res;
        display_name = displayname;
    }).catch((err) => {
        console.log(err);
    });

    extendMatrixClient(client);

    // await client.rehydrateDevice();

    await client.initCrypto();
    await client.startClient();
}

const Logout = async () => {
    if (client == null) {
        alert('not Login..');
        return
    }

    client.stopClient();
    client.removeAllListeners();
    await client.logout();
    await client.clearStores();
    log.log("Logged out");
}

const Register = async () => {
    if (client != null) {
        alert("Login Ready..");
        return
    }

    var user_name = regis_username.value;
    var password = regis_password.value;
    var auth = { "type": "m.login.dummy" };

    const registrationClient = matrixcs.createClient(BASE_URL);

    const userRegisterResult = await registrationClient.register(
        user_name,
        password,
        null,
        auth
    );

    // update user info when register success
    user_id = userRegisterResult.user_id;
    access_token = userRegisterResult.access_token;
    home_server = userRegisterResult.home_server;
    device_id = userRegisterResult.device_id;

    client = matrixcs.createClient({
        baseUrl: BASE_URL,
        userId: user_id,
        accessToken: access_token,
        deviceId: device_id,
        sessionStore: new matrixcs.WebStorageSessionStore(window.localStorage),
        cryptoStore: new matrixcs.MemoryCryptoStore(),
    });

    extendMatrixClient(client);

    await client.initCrypto();
    await client.startClient();

    return client;

}

const registerGuest = async () => {

    if (client != null) {
        alert("Login Ready..");
        return
    }
    client = matrixcs.createClient(BASE_URL);
    client.registerGuest().then((res) => {

        // update user info when register guest success
        user_id = res.user_id;
        access_token = res.access_token;
        home_server = res.home_server;
        device_id = res.device_id;

        console.log(res)
    }).catch((err) => {
        console.log(err);
    });

    extendMatrixClient(client);
}

const authUploadDeviceSigningKeys = async (makeRequest) => {
    makeRequest();
    return Promise.resolve();
}

const initBootstrapCrossSigning = async () => {


    const isCrossSigningReady = await client.isCrossSigningReady();
    if (isCrossSigningReady) {
        return;
    } else {
        // set up cross-signing and restore key backup
        await client.bootstrapSecretStorage();
        const { backupInfo } = await client.checkKeyBackup();
        client.enableKeyBackup(backupInfo); // FIXME: it doesn't seem to be uploading keys
        client.restoreKeyBackupWithSecretStorage(backupInfo);
    }

    await client.bootstrapCrossSigning(authUploadDeviceSigningKeys);
    client.uploadKeySignatures();
}

const GeneratePassPhrase = async () => {
    if (ssss_key.value == '') {
        alert("Please input key");
        return
    }
    const passPhrase = await client.createRecoveryKeyFromPassphrase(ssss_key.value);
    encodedPrivateKey_text.value = passPhrase.encodedPrivateKey;
    passphrase = ssss_key.value;

    await client.bootstrapSecretStorage({
        createSecretStorageKey: async () => passPhrase,
        setupNewKeyBackup: true,
        setupNewSecretStorage: true,
    });
    await client.bootstrapCrossSigning({
        authUploadDeviceSigningKeys: authUploadDeviceSigningKeys,
        setupNewCrossSigning: true
    });

    const prepare_key_data = await client.prepareKeyBackupVersion(passphrase, {
        secureSecretStorage: true
    });

    await client.createKeyBackupVersion(prepare_key_data);
}

const VerifiedLogin_SecureKey = async () => {

    if (!secure_key_text.value && !secure_key_file.value && !passphrase_text.value) {
        alert("Please input secure key");
        return;
    }

    if (secure_key_text.value && secure_key_file.value && passphrase_text.value) {
        alert("Please select just one input for key");
        return;
    }

    if (secure_key_text.value) {
        secure_key = secure_key_text.value;
    } else if (passphrase_text.value) {
        passphrase = passphrase_text.value;
    } else {
        let file = secure_key_file.files[0];
        let reader = new FileReader();
        reader.addEventListener('load', function (e) {
            let text = e.target.result;
            secure_key = text;
        });
        reader.readAsText(file);
    }

    initBootstrapCrossSigning();
}

const isRoomEncrypted = async (room_id) => {
    var is_encrypted = client.isRoomEncrypted(room_id);
    if (is_encrypted) {
        document.getElementById(room_id).style.color = "red";
    }
}

const getAllRoom = async () => {
    if (client == null) {
        alert("Not Login..");
        return
    }

    var rooms = client.getRooms();
    $('#list_all_room li').remove();
    rooms.forEach(room => {
        var room_id_tmp = room.roomId;
        var room_name = room.name;
        $("#list_all_room").append('<li><input type="text" id="' + room_id_tmp + '" value=' + room_id_tmp + '><input type="text" value=' + room_name + '></li>');
        isRoomEncrypted(room_id_tmp);
    });
}

const setRoomVerified = async (room) => {

    let members = (await room.getEncryptionTargetMembers()).map(x => x["userId"])
    let memberkeys = await client.downloadKeys(members);

    for (const userId in memberkeys) {
        for (const deviceId in memberkeys[userId]) {
            await client.setDeviceVerified(userId, deviceId);
        }
    }
}

const setDeviceVerified = async () => {

    var rooms = client.getRooms();
    rooms.forEach(room => {
        const roomId = room.roomId;
        const roomX = client.getRoom(roomId);
        setRoomVerified(roomX);
    })
}

const createRoom = async () => {

    if (client == null) {
        alert("Not Login..");
        return
    }

    var room_alias_name = RoomAliasName.value;
    var name = RoomName.value;
    var topic = RoomTopic.value;
    var visibility = $("input[name='visibility']:checked").val();
    var invite_list_html = $("input[name=user_invite]");
    var invite_list = [];

    for (var i = 0; i < invite_list_html.length; i++) {
        if (invite_list_html[i].value) {
            invite_list.push(invite_list_html[i].value);
        }
    }

    var options = {
        room_alias_name: room_alias_name,
        visibility: visibility,
        invite: invite_list,
        name: name,
        topic: topic
    }

    const RoomInfo = await client.createRoom(options);
    const roomId = RoomInfo.room_id;
    const roomAliasName = RoomInfo.room_alias;

    // matrixClient.setRoomEncryption() only updates local state
    // so we do it ourselves with 'sendStateEvent'
    await client.sendStateEvent(
        roomId, 'm.room.encryption', ROOM_CRYPTO_CONFIG,
    );
    await client.setRoomEncryption(
        roomId, ROOM_CRYPTO_CONFIG,
    );

    showRoomCreateID.value = roomId;
    showRoomAlias.value = roomAliasName;
}
const leaveRoom = async () => {
    if (client == null) {
        alert("not login..");
        return
    }

    var roomID = RoomIDtoDeltxt.value;

    client.leave(roomID);
}
const deleteRoom = async () => {
    var roomID = RoomIDtoDeltxt.value;

    client.forget(roomID, true).then((res) => {
        var id_ui = "#" + roomID;
        $(id_ui).remove();
    }).catch((err) => {
        console.log(err);
    });
}

const decryption_timeline = async (timeline) => {
    timeline.forEach(t => {
        client.decryptEventIfNeeded(t, { isRetry: true, emit: true })
    })
}

const scrollback = async (room) => {
    const limit = 30;
    client.scrollback(room, limit).then((res) => {
        decryption_timeline(res.timeline);
    }).catch((error) => {
        console.log(error);
    })
}

const startChat = async () => {

    if (client == null) {
        alert("Not Login..");
        return
    }

    var RoomId = RoomIDtoChat.value;
    var room = client.getRoom(RoomId);

    $("#messageToSent").show();
    $("#sentMessage").show();


    client.getCapabilities();
    client.getPublicisedGroups([user_id]);

    scrollback(room);
    ActiveRoom = RoomId;
}

const sendMessageToRooms = async () => {

    var RoomId = RoomIDtoChat.value;
    var sentContent = messageToSent.value;
    var content = {
        "body": sentContent,
        "msgtype": "m.text"
    };

    client.sendMessage(
        RoomId,
        content
    ).then((res) => {
        $("#message").append('<li>[' + display_name + '] : ' + sentContent + '</li>');
    }).catch((err) => {
        console.log(err)
    });
}


const verifiedCrossSigning = async () => {

    // m.key.verification.request
    var TxnId = client.makeTxnId();
    transaction_request = TxnId;

    var content = {};
    content[user_id] = {
        "*": {
            "from_device": device_id,
            "methods": [
                "m.sas.v1"
            ],
            "timestamp": Date.now(),
            "transaction_id": TxnId
        }
    }
    client.sendToDevice("m.key.verification.request", content, TxnId);
}

const requestVerifiedReady = async () => {

    // m.key.verification.ready

    var TxnId = client.makeTxnId();

    var content = {};
    content[user_id] = {
        "*": {
            "from_device": device_id,
            "methods": [
                "m.sas.v1"
            ],
            "transaction_id": TxnId
        }
    }
    client.sendToDevice("m.key.verification.ready", content, TxnId);
}

const requestVerifiedStart = async () => {

    // m.key.verification.start

    var TxnId = client.makeTxnId();

    var content = {};
    var device_info = {}
    device_info[requestDeviceId] = {
        "method": "m.sas.v1",
        "from_device": device_id,
        "key_agreement_protocols": ["curve25519-hkdf-sha256", "curve25519"],
        "hashes": ["sha256"],
        "message_authentication_codes": ["hkdf-hmac-sha256", "hmac-sha256"],
        "short_authentication_string": ["decimal", "emoji"],
        "transaction_id": request_transactionId
    }
    content[user_id] = device_info;

    client.sendToDevice("m.key.verification.start", content, TxnId);
}

const requestVerifiedDone = async () => {
    // m.key.verification.ready

    var TxnId = client.makeTxnId();

    var content = {};
    content[user_id] = {
        "*": {
            "transaction_id": TxnId
        }
    }
    client.sendToDevice("m.key.verification.done", content, TxnId);
}

const requestCancel = async () => {

    // m.key.verification.cancel

    var TxnId = client.makeTxnId();

    var content = {};
    var device_info = {}
    device_info[requestDeviceId] = {
        "code": "m.user",
        "reason": "User rejected the key verification request",
        "transaction_id": request_transactionId
    }
    content[user_id] = device_info;

    client.sendToDevice("m.key.verification.cancel", content, TxnId);
}

function extendMatrixClient(client) {
    // automatic join
    client.on('RoomMember.membership', async (event, member) => {
        if (member.membership === 'invite' && member.userId === client.getUserId()) {
            await client.joinRoom(member.roomId);
            // setting up of room encryption seems to be triggered automatically
            // but if we don't wait for it the first messages we send are unencrypted
            await client.setRoomEncryption(member.roomId, { algorithm: 'm.megolm.v1.aes-sha2' })
        }
    });

    client.on("RoomMember.typing", function (event, member) {
        if (member.typing) {
            $("#message").append('<li class="is_typing">[' + member.name + '] : ' + " is typing..." + '</li>');
        }
        else {
            $('.is_typing').each(function (index) {
                $(this).remove();
            });
        }
    });

    client.on("crypto.devicesUpdated", function (event, room, toStartOfTimeline) {
        setDeviceVerified();
    });

    client.onDecryptedMessage = (message, sender_name) => {
        $("#message").append('<li>[' + sender_name + '] : ' + message + '</li>');
    }

    client.on('Event.decrypted', (event) => {
        if (ActiveRoom == "") {
            return
        }

        if (event.getType() === 'm.room.message' && event.getRoomId() == ActiveRoom) {
            client.onDecryptedMessage(event.getContent().body, event.sender.name);
        } else {
            console.log('decrypted an event of type', event.getType());
        }
    });

    client.on("crypto.verification.request", function (event) {
        const eventsByThemKeys = event.eventsByThem.keys();
        const eventsByThem = eventsByThemKeys.next().value;
    });
    client.on("Room.timeline", function (event, room, toStartOfTimeline) {
        // we know we only want to respond to messages
        if (event.getType() !== "m.room.message") {
            return;
        }

        // we are only intested in messages from the test room, which start with "!"
        if (event.getRoomId() === ActiveRoom && event.getContent().body[0] === '!') {
            console.log(event.getContent().body, "!!!")
        }
    });
}


// event click sesstion
Loginbtn.addEventListener('click', LoginUser);
Registerbtn.addEventListener('click', Register);
register_guestbtn.addEventListener('click', registerGuest);
logoutBTN.addEventListener('click', Logout);
create_ssss_key_btn.addEventListener('click', GeneratePassPhrase);
verifiyKeybtn.addEventListener('click', VerifiedLogin_SecureKey);
GetAllRoombtn.addEventListener('click', getAllRoom);
StartChatbtn.addEventListener('click', startChat);
VerifiedBtn.addEventListener('click', verifiedCrossSigning);
createRoombtn.addEventListener('click', createRoom);
delRoombtn.addEventListener('click', deleteRoom);
Leavebtn.addEventListener('click', leaveRoom);
sentMessagebtn.addEventListener('click', sendMessageToRooms);
randomKeybtn.addEventListener('click', generateRandomKeyUser);
copyGenKeybtn.addEventListener('click', copyKeyUser);