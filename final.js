import * as THREE from "three";
import {
    OrbitControls
} from "https://cdn.jsdelivr.net/npm/three@0.157.0/examples/jsm/controls/OrbitControls.js";
import {
    EffectComposer
} from "https://cdn.jsdelivr.net/npm/three@0.157.0/examples/jsm/postprocessing/EffectComposer.js";
import {
    RenderPass
} from "https://cdn.jsdelivr.net/npm/three@0.157.0/examples/jsm/postprocessing/RenderPass.js";
import {
    AfterimagePass
} from "https://cdn.jsdelivr.net/npm/three@0.157.0/examples/jsm/postprocessing/AfterimagePass.js";
import {
    makeMat
} from "./materials.min.js";

const appData = window.dataMemoryHeartLoveLoom?.data || {};

// Táº®T HOÃ€N TOÃ€N VIá»†C SPAWN Tá»ª Tá»ªNG Tá»ª - CHá»ˆ DÃ™NG CÃ‚U CHÃšC LÆ  Lá»¬NG
let allWordsFlat = [];
const originalTexts = appData.messages || [];
originalTexts.forEach(sentence => {
    const words = sentence.split(' ');
    allWordsFlat.push(...words);
});

let currentWordIndex = 0;
let nextWordSpawnTime = 0;
const WORD_SPAWN_INTERVAL = 0.4;

const IMAGE_CONFIG = {
    paths: appData.images || [],
    count: appData.images?.length || 0,
    scale: 2.5,
    glowIntensity: .4,
    spawnRate: .18,
    maxActiveImages: 45,
    spawnInterval: 400
};
// MÃ u trÃ¡i tim to luÃ´n lÃ  Ä‘á», khÃ´ng thay Ä‘á»•i
const heartInitialColor = new THREE.Color('#FF69B4');

let imageTextures = [],
    imageLoadingComplete = !1,
    imagePool = [],
    activeImages = new Map,
    freeImageIndices = [],
    currentImageIndex = 0,
    lastImageSpawnTime = 0,
    imageSpawnQueue = [],
    minActiveImages = 8,
    maxConcurrentImages = 24,
    lastStatusLogTime = 0,
    independentImageSprites = [],
    nextIndependentSpawnTime = 0;
const textureLoader = new THREE.TextureLoader;
textureLoader.setCrossOrigin('anonymous');
async function fetchAndPrepareImageTextures() {
    try {
        const t = IMAGE_CONFIG.paths.map(t => new Promise((e, a) => {
            textureLoader.load(t, t => {
                // Giá»¯ chiá»u áº£nh Ä‘Ãºng (khÃ´ng bá»‹ láº­t ngÆ°á»£c)
                t.flipY = !1;
                t.minFilter = THREE.LinearFilter;
                t.magFilter = THREE.LinearFilter;
                t.format = THREE.RGBAFormat;
                t.needsUpdate = !0;
                e(t);
            }, void 0, t => {
                const a = document.createElement("canvas");
                a.width = a.height = 512;
                const o = a.getContext("2d"),
                    s = o.createRadialGradient(256, 256, 0, 256, 256, 256);
                s.addColorStop(0, "#ff69b4"), s.addColorStop(1, "#ff1493"), o.fillStyle = s, o.fillRect(0, 0, 512, 512);
                const r = new THREE.CanvasTexture(a);
                r.needsUpdate = !0, e(r)
            })
        }));
        return imageTextures = await Promise.all(t), !0
    } catch (t) {
        return !1
    }
}

function buildImageSpriteMaterial(t, e = 1) {
    return new THREE.SpriteMaterial({
        map: t,
        transparent: !0,
        opacity: e,
        depthWrite: !1,
        alphaTest: .1,
        sizeAttenuation: !0
    })
}

function getAspectRatioAdjustedScale(t, e = 2.5) {
    if (!t || !t.image) return e;
    const a = t.image.width / t.image.height;
    return {
        x: a > 1 ? e : e * a,
        y: a > 1 ? e / a : e
    }
}
async function setupImageStreaming() {
    imageLoadingComplete = await fetchAndPrepareImageTextures(), imageLoadingComplete && tweakSpawnParametersByImageCount()
}

function tweakSpawnParametersByImageCount() {
    const t = IMAGE_CONFIG.count;
    t <= 2 ? (IMAGE_CONFIG.spawnInterval = 300, minActiveImages = 6, maxConcurrentImages = Math.min(15, 7.5 * t)) : t <= 5 ? (IMAGE_CONFIG.spawnInterval = 400, minActiveImages = 8, maxConcurrentImages = Math.min(18, 3.5 * t)) : (IMAGE_CONFIG.spawnInterval = 500, minActiveImages = 8, maxConcurrentImages = Math.min(30, Math.ceil(2.5 * t)))
}

function printImageSystemReport() {
    activeImages.size, independentImageSprites.length, freeImageIndices.length, imageSpawnQueue.length
}

function setupImageObjectPool() {
    if (imageLoadingComplete && streamHeart) {
        imagePool.forEach(t => {
            t && t.parent && t.parent.remove(t)
        }), imagePool.length = 0, activeImages.clear(), freeImageIndices.length = 0;
        for (let t = 0; t < IMAGE_CONFIG.maxActiveImages; t++) {
            const e = t % IMAGE_CONFIG.count,
                a = imageTextures[e],
                o = buildImageSpriteMaterial(a, 1),
                s = new THREE.Sprite(o),
                r = getAspectRatioAdjustedScale(a, IMAGE_CONFIG.scale);
            s.scale.set(r.x, r.y, 1), s.visible = !1, s.userData = {
                poolIndex: t,
                textureIndex: e,
                isActive: !1,
                particleIndex: -1,
                aspectScale: r
            }, streamHeart.add(s), imagePool.push(s), freeImageIndices.push(t)
        }
    }
}

function retrieveImageFromPool(t) {
    if (0 === freeImageIndices.length) return null;
    const e = freeImageIndices.pop(),
        a = imagePool[e],
        o = currentImageIndex % IMAGE_CONFIG.count,
        s = imageTextures[o];
    a.material.map = s, a.material.needsUpdate = !0;
    const r = getAspectRatioAdjustedScale(s, IMAGE_CONFIG.scale);
    return a.scale.set(r.x, r.y, 1), a.userData.aspectScale = r, a.userData.textureIndex = o, a.userData.isActive = !0, a.userData.particleIndex = t, activeImages.set(t, e), currentImageIndex = (currentImageIndex + 1) % IMAGE_CONFIG.count, a
}

function releaseImageToPool(t) {
    const e = activeImages.get(t);
    if (void 0 !== e) {
        const a = imagePool[e];
        a.visible = !1, a.material.opacity = 0, a.userData.isActive = !1, a.userData.particleIndex = -1, activeImages.delete(t), freeImageIndices.push(e)
    }
}

// Táº¯t hoÃ n toÃ n viá»‡c gáº¯n áº£nh bay theo háº¡t/Ä‘Ä©a
function controlImageSpawningLogic(t) {
    return;
}

function createFloatingImageSprite(t) {
    return;
}

function animateFloatingImageSprites(t) {
    return;
}

function selectBestParticleForImageSpawn() {
    const t = [];
    for (let e = 0; e < streamCount; e++)
        if (!activeImages.has(e)) {
            const a = streamState[e];
            t.push({
                index: e,
                state: a,
                priority: a === STATE_ASCEND ? 3 : a === STATE_ON_DISK ? 2 : 1
            })
        } return 0 === t.length ? -1 : (t.sort((t, e) => e.priority - t.priority), t[0].index)
}

function handleQueuedImageSpawns() {
    imageSpawnQueue.length = 0;
    return;
}

function applyMobileSpecificSettings() {
    if (!document.querySelector('meta[name="viewport"]')) {
        const t = document.createElement("meta");
        t.name = "viewport", t.content = "width=device-width, initial-scale=1.0, user-scalable=no", document.head.appendChild(t)
    }
    document.body.style.overflow = "hidden", document.body.style.position = "fixed", document.body.style.width = "100%", document.body.style.height = "100%", /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) && renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
}
setupImageStreaming();
let STAR_COUNT = 0,
    starAlpha = null,
    starPhase = null,
    starGeo = null,
    cosmicDust = null; // sáº½ Ä‘Æ°á»£c khá»Ÿi táº¡o trá»… Ä‘á»ƒ trÃ¡nh cháº·n render ban Ä‘áº§u
const RingText = [...appData.messages];

let cameraAnimationStart = null;
const CAMERA_ANIMATION_DURATION = 2.5;
let CAMERA_START_POSITION = {
    x: 0,
    y: 90,
    z: 30
};
const CAMERA_END_POSITION = {
    x: 0,
    y: 25,
    z: 65
};
let userHasMovedCamera = !1,
    streamHeartStarted = !1,
    streamHeartActiveRatio = 0,
    firstResetCompleted = !1;
const scene = new THREE.Scene,
    heartScene = new THREE.Scene,
    renderer = new THREE.WebGLRenderer({
        antialias: !0,
        alpha: !0
    }),
    HEART_ROTATE = !1;
let heartbeatEnabled = !1;
const fadeObjects = [];


const explosionEffects = []; // Máº£ng Ä‘á»ƒ quáº£n lÃ½ cÃ¡c hiá»‡u á»©ng bÃ¹ng ná»•
const effectPool = { // Má»™t object Ä‘á»ƒ chá»©a táº¥t cáº£ cÃ¡c há»“ hiá»‡u á»©ng
    waves: [],
    sparkles: [],
    texts: []
};
const POOL_SIZE = 5; // Táº¡o sáºµn 5 hiá»‡u á»©ng, Ä‘á»§ Ä‘á»ƒ xá»­ lÃ½ cÃ¡c click nhanh
const activeTexts = new Map(); // <<< THÃŠM DÃ’NG NÃ€Y: Quáº£n lÃ½ cÃ¡c chá»¯ Ä‘ang bay

let isPulsing = false;
let pulseStartTime = 0;
const PULSE_DURATION = 0.6;   // Nhá»‹p Ä‘áº­p kÃ©o dÃ i 0.6 giÃ¢y
const PULSE_AMPLITUDE = 0.15; // Phá»“ng to hÆ¡n 15%

// Biáº¿n lÆ°u rotation tÃ­ch luá»¹ cho Ä‘Ä©a áº£nh vÃ  ribbon (thay vÃ¬ dá»±a trÃªn thá»i gian tuyá»‡t Ä‘á»‘i Ä‘á»ƒ cÃ³ thá»ƒ boost tá»‘c Ä‘á»™)
let planeRotationAngle = 0;
let spinBoostUntil = 0;

let revealStart = null;
const REVEAL_DURATION = 1.5,
    HEARTBEAT_FREQ_HZ = .5,
    HEARTBEAT_AMPLITUDE = .05,
    STAGE = {
        RIBBON: 0,
        STREAM: 1,
        STAR: 2,
        SHOOT: 3,
        HEART: 4
    },
    STAGE_DURATION = .15;
renderer.setPixelRatio(window.devicePixelRatio), renderer.setSize(window.innerWidth, window.innerHeight), document.body.appendChild(renderer.domElement), applyMobileSpecificSettings();
let staticBottomHeart = null,
    staticTopHeart = null;
const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, .1, 300);
camera.position.set(0, 90, 25), camera.lookAt(0, 0, 0);
const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = !0, controls.minDistance = 5, controls.maxDistance = 100, controls.enableZoom = !0, controls.minPolarAngle = THREE.MathUtils.degToRad(60), controls.maxPolarAngle = THREE.MathUtils.degToRad(135), controls.enablePan = !0;

// Táº O Máº¶T PHáº²NG VÃ” HÃŒNH Äá»‚ Báº®T Vá»Š TRÃ CLICK
const planeGeo1 = new THREE.PlaneGeometry(30, 30);
const planeMat = new THREE.MeshBasicMaterial({
    color: 0xff00ff,
    side: THREE.DoubleSide,
    visible: false // Quan trá»ng: lÃ m cho nÃ³ vÃ´ hÃ¬nh
});
const invisiblePlane = new THREE.Mesh(planeGeo1, planeMat);
invisiblePlane.rotation.z = Math.PI; // Xoay cho khá»›p vá»›i trÃ¡i tim
invisiblePlane.position.y = 10;     // Äáº·t á»Ÿ Ä‘á»™ cao cá»§a trÃ¡i tim
scene.add(invisiblePlane);

const composerMain = new EffectComposer(renderer),
    renderPassMain = new RenderPass(scene, camera);
renderPassMain.clear = !1, composerMain.addPass(renderPassMain);
const composerHeart = new EffectComposer(renderer);
composerHeart.addPass(new RenderPass(heartScene, camera));
const afterimagePass = new AfterimagePass;
afterimagePass.uniforms.damp.value = .9, composerHeart.addPass(afterimagePass), scene.add(new THREE.AmbientLight(16777215, .6));
const p1 = new THREE.PointLight(16777215, 1.2);
p1.position.set(10, 10, 10), scene.add(p1);
const p2 = new THREE.PointLight(16744703, .8);

function generateGlowCircleTexture() {
    const t = document.createElement("canvas");
    t.width = 256, t.height = 256;
    const e = t.getContext("2d"),
        a = 128,
        o = e.createRadialGradient(a, a, .4 * 127, a, a, 127);
    o.addColorStop(0, "rgba(255,105,180,0.6)"), o.addColorStop(1, "rgba(255,20,147,0)"), e.fillStyle = o, e.beginPath(), e.arc(a, a, 127, 0, 2 * Math.PI), e.closePath(), e.fill();
    const s = e.createRadialGradient(a, a, 0, a, a, 76.2);
    s.addColorStop(0, "rgba(255,255,255,1)"), s.addColorStop(1, "rgba(255,255,255,0)"), e.fillStyle = s, e.beginPath(), e.arc(a, a, 76.2, 0, 2 * Math.PI), e.closePath(), e.fill();
    const r = new THREE.CanvasTexture(t);
    return r.minFilter = THREE.LinearFilter, r.magFilter = THREE.LinearFilter, r.needsUpdate = !0, r
}
p2.position.set(-10, -10, -10), scene.add(p2);
const circleTexture = generateGlowCircleTexture(),
    heartShape = new THREE.Shape,
    x = 0,
    y = 0;
heartShape.moveTo(5, 5), heartShape.bezierCurveTo(5, 5, 4, 0, 0, 0), heartShape.bezierCurveTo(-6, 0, -6, 7, -6, 7), heartShape.bezierCurveTo(-6, 11, -3, 15.4, 5, 19), heartShape.bezierCurveTo(12, 15.4, 16, 11, 16, 7), heartShape.bezierCurveTo(16, 7, 16, 0, 10, 0), heartShape.bezierCurveTo(7, 0, 5, 5, 5, 5);
const polyPts = heartShape.getPoints(100);

function isPointInsidePolygon(t, e) {
    let a = !1;
    for (let o = 0, s = e.length - 1; o < e.length; s = o++) {
        const r = e[o].x,
            i = e[o].y,
            n = e[s].x,
            l = e[s].y;
        i > t.y != l > t.y && t.x < (n - r) * (t.y - i) / (l - i) + r && (a = !a)
    }
    return a
}
const polyShift = polyPts.map(t => ({
    x: t.x - 5,
    y: t.y - 7
})),
    BORDER_THRESHOLD = .1 * (Math.max(...polyPts.map(t => t.x)) - Math.min(...polyPts.map(t => t.x)));

function calculateMinimumDistanceToBorder(t, e) {
    let a = 1 / 0;
    for (let o = 0; o < polyShift.length; o++) {
        const s = polyShift[o],
            r = polyShift[(o + 1) % polyShift.length],
            i = r.x - s.x,
            n = r.y - s.y,
            l = ((t - s.x) * i + (e - s.y) * n) / (i * i + n * n),
            m = Math.max(0, Math.min(1, l)),
            c = t - (s.x + m * i),
            p = e - (s.y + m * n),
            d = c * c + p * p;
        d < a && (a = d)
    }
    return Math.sqrt(a)
}
// Khá»Ÿi táº¡o cÃ¡c Ä‘á»‘i tÆ°á»£ng cáº§n thiáº¿t má»™t láº§n Ä‘á»ƒ tá»‘i Æ°u hiá»‡u suáº¥t
const raycaster = new THREE.Raycaster();
const mouse = new THREE.Vector2();
const HEART_CENTER_TARGET = new THREE.Vector3(0, 10, 0);
// HÃ m táº¡o hiá»‡u á»©ng bÃ¹ng ná»• táº¡i vá»‹ trÃ­ click
function createHeartExplosion(event) {
    // 1. Chuyá»ƒn Ä‘á»•i tá»a Ä‘á»™ mÃ n hÃ¬nh (pixel) thÃ nh tá»a Ä‘á»™ 3D
    mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

    // 2. Báº¯n má»™t tia tá»« camera qua Ä‘iá»ƒm click
    raycaster.setFromCamera(mouse, camera);

    // 3. THAY VÃŒ KIá»‚M TRA VA CHáº M, CHÃšNG TA TÃNH TOÃN TRá»°C TIáº¾P Má»˜T ÄIá»‚M
    // Äiá»ƒm nÃ y náº±m trÃªn tia báº¯n ra, cÃ¡ch camera má»™t khoáº£ng cá»‘ Ä‘á»‹nh.
    const explosionDistance = 60; // Khoáº£ng cÃ¡ch tá»« camera tá»›i Ä‘iá»ƒm ná»•, báº¡n cÃ³ thá»ƒ Ä‘iá»u chá»‰nh
    const intersectionPoint = new THREE.Vector3();

    // Láº¥y Ä‘iá»ƒm báº¯t Ä‘áº§u (vá»‹ trÃ­ camera) vÃ  hÆ°á»›ng cá»§a tia
    // Sau Ä‘Ã³ tÃ­nh Ä‘iá»ƒm cuá»‘i báº±ng cÃ´ng thá»©c: Äiá»ƒm = Vá»‹ trÃ­ báº¯t Ä‘áº§u + HÆ°á»›ng * Khoáº£ng cÃ¡ch
    raycaster.ray.at(explosionDistance, intersectionPoint);

    // 4. Táº¡o hiá»‡u á»©ng bÃ¹ng ná»• táº¡i Ä‘iá»ƒm Ä‘Ã£ tÃ­nh toÃ¡n
    const explosionGroup = new THREE.Group();
    const explosionMat = makeMat({
        map: circleTexture,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        alphaSupport: true,
        vertexColors: true
    });

    const count = 30 + Math.random() * 20;
    const positions = [];
    const colors = [];
    const sizes = [];
    const velocities = [];

    const baseColor = new THREE.Color().setHSL(Math.random(), 0.9, 0.7);

    for (let i = 0; i < count; i++) {
        positions.push(intersectionPoint.x, intersectionPoint.y, intersectionPoint.z);

        const color = baseColor.clone().offsetHSL(Math.random() * 0.2 - 0.1, 0, 0);
        colors.push(color.r, color.g, color.b);

        sizes.push(Math.random() * 0.8 + 0.2);

        const phi = Math.random() * Math.PI * 2;
        const theta = Math.acos(Math.random() * 2 - 1);
        const speed = Math.random() * 15 + 10;

        const velocity = new THREE.Vector3();
        velocity.setFromSphericalCoords(1, phi, theta);
        velocities.push(velocity.multiplyScalar(speed));
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    geo.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));

    const points = new THREE.Points(geo, explosionMat);

    explosionGroup.add(points);
    explosionGroup.userData.velocities = velocities;
    explosionGroup.userData.life = 1.0;

    scene.add(explosionGroup);
    explosionEffects.push(explosionGroup);
}
// HÃ m khá»Ÿi táº¡o táº¥t cáº£ hiá»‡u á»©ng vÃ o "há»“ chá»©a" Ä‘á»ƒ tÃ¡i sá»­ dá»¥ng
function setupEffectPools() {
    // Táº¡o texture má»™t láº§n duy nháº¥t
    const canvas = document.createElement('canvas');
    canvas.width = 256; canvas.height = 256;
    const context = canvas.getContext('2d');
    const gradient = context.createRadialGradient(128, 128, 0, 128, 128, 128);
    gradient.addColorStop(0, 'rgba(255,255,255,1)');
    gradient.addColorStop(0.3, 'rgba(255,255,255,0.5)'); // LÃ m cáº¡nh má»m hÆ¡n
    gradient.addColorStop(1, 'rgba(255,255,255,0)');
    context.fillStyle = gradient;
    context.fillRect(0, 0, 256, 256);
    const waveTexture = new THREE.CanvasTexture(canvas);

    for (let i = 0; i < POOL_SIZE; i++) {
        // --- Khá»Ÿi táº¡o SÃ³ng NÄƒng LÆ°á»£ng ---
        const waveMat = new THREE.MeshBasicMaterial({
            map: waveTexture,
            blending: THREE.AdditiveBlending,
            transparent: true,
            depthWrite: false
        });
        const wave = new THREE.Mesh(new THREE.PlaneGeometry(20, 20), waveMat);
        wave.visible = false;
        wave.userData.active = false;
        scene.add(wave);
        effectPool.waves.push(wave);

        // --- Khá»Ÿi táº¡o Bá»¥i Sao ---
        const SPARKLE_COUNT = 100; // Giáº£m sá»‘ lÆ°á»£ng háº¡t
        const sparkleGeo = new THREE.BufferGeometry();
        // Cáº¥p phÃ¡t bá»™ nhá»› trÆ°á»›c cho cÃ¡c thuá»™c tÃ­nh
        sparkleGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(SPARKLE_COUNT * 3), 3).setUsage(THREE.DynamicDrawUsage));
        const sparkleMat = makeMat({ map: circleTexture, blending: THREE.AdditiveBlending, alphaSupport: true, depthWrite: false });
        const sparkles = new THREE.Points(sparkleGeo, sparkleMat);
        sparkles.visible = false;
        sparkles.userData.active = false;
        scene.add(sparkles);
        effectPool.sparkles.push(sparkles);
    }

    // Khá»Ÿi táº¡o Text Sprites
    const textsToCreate = appData?.messages || [];
    // --- KHá»žI Táº O TEXT SPRITES CHO Tá»ªNG Tá»ª - Táº®T VÃŒ CHá»ˆ DÃ™NG ORBITING WISHES ---
    // KhÃ´ng táº¡o text sprites cho tá»«ng tá»« ná»¯a
    /*
    const allWords = (appData?.messages || []).join(' ').split(' ');
    const uniqueWords = [...new Set(allWords.filter(word => word.length > 0))];

    uniqueWords.forEach(word => {
        const textTexture = createFlyingTextTexture(word);
        const textMat = new THREE.SpriteMaterial({
            map: textTexture,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });
        const textSprite = new THREE.Sprite(textMat);

        const aspectRatio = textTexture.image.width / textTexture.image.height;
        textSprite.scale.set(aspectRatio * 1.5, 1.5, 1);

        textSprite.visible = false;
        textSprite.userData.active = false;
        textSprite.userData.text = word;
        streamHeart.add(textSprite);
        effectPool.texts.push(textSprite);
    });
    */
    // --- Káº¾T THÃšC: KHá»žI Táº O TEXT SPRITES ---
    
    // --- Táº®T TEXT SPRITES CHO MESSAGES - VÃŒ CHá»ˆ DÃ™NG ORBITING WISHES ---
    /*
    textsToCreate.forEach(text => {
        const textTexture = createFlyingTextTexture(text);
        const textMat = new THREE.SpriteMaterial({
            map: textTexture,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });
        const textSprite = new THREE.Sprite(textMat);

        const aspectRatio = textTexture.image.width / textTexture.image.height;
        textSprite.scale.set(aspectRatio * 2, 2, 1);

        textSprite.visible = false;
        textSprite.userData.active = false;
        streamHeart.add(textSprite);
        effectPool.texts.push(textSprite);
    });
    */
}
function releaseTextToPool(particleIndex) {
    if (activeTexts.has(particleIndex)) {
        const sprite = activeTexts.get(particleIndex);
        sprite.visible = false;
        sprite.userData.active = false;
        activeTexts.delete(particleIndex);
    }
}
function createFlyingTextTexture(text) {
    const canvas = document.createElement("canvas");
    // KÃ­ch thÆ°á»›c canvas lá»›n hÆ¡n Ä‘á»ƒ chá»¯ nÃ©t hÆ¡n
    canvas.width = 1024;
    canvas.height = 128;
    const context = canvas.getContext("2d");
    context.font = 'bold 70px "Noto Sans", "Noto Sans JP", "Noto Sans KR", "Noto Sans SC", "Noto Sans TC", "Noto Sans Arabic", "Noto Sans Devanagari", "Noto Sans Hebrew", "Noto Sans Thai", sans-serif';
    context.textAlign = "center";
    context.textBaseline = "middle";

    // ThÃªm viá»n mÃ u Ä‘á»ƒ chá»¯ ná»•i báº­t
    context.strokeStyle = "rgba(160, 30, 95, 0.9)";
    context.lineWidth = 8;
    context.strokeText(text, canvas.width / 2, canvas.height / 2);

    // ThÃªm lá»›p mÃ u tráº¯ng bÃªn trong
    context.fillStyle = "#ffffff";
    context.fillText(text, canvas.width / 2, canvas.height / 2);

    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    texture.magFilter = THREE.LinearFilter;
    return texture;
}

// --- 5 CÃ‚U CHÃšC NGáº®N XOAY QUANH KHÃ”NG GIAN (mÃ u há»“ng, font Pacifico) ---
// DÃ¹ng data tá»« load-valentine-data.js (window.WISH_SENTENCES), khÃ´ng cÃ³ data máº«u
let WISH_SENTENCES = (typeof window !== 'undefined' && Array.isArray(window.WISH_SENTENCES)) ? window.WISH_SENTENCES : [];
if (typeof window !== 'undefined') {
    window.WISH_SENTENCES = WISH_SENTENCES;
}
const ORBIT_WISH_COUNT = 80;
const ORBIT_WISH_PINK = "#ff69b4";
const ORBIT_WISH_PINK_STROKE = "rgba(255, 20, 147, 0.9)";
const ORBIT_WISH_APPEAR_SPAN = 8;   // CÃ¢u chÃºc xuáº¥t hiá»‡n tráº£i Ä‘á»u trong 8 giÃ¢y
const ORBIT_WISH_FADE_DURATION = 1.5; // Má»—i cÃ¢u fade-in 1.5 giÃ¢y
let orbitingWishGroup = null;
let orbitingWishAppearStart = null;  // Thá»i Ä‘iá»ƒm báº¯t Ä‘áº§u cho staggered fade-in

function createOrbitingWishTexture(text) {
    const canvas = document.createElement("canvas");
    canvas.width = 1024;
    canvas.height = 140;
    const ctx = canvas.getContext("2d");
    ctx.font = '72px "Pacifico", cursive';
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.strokeStyle = ORBIT_WISH_PINK_STROKE;
    ctx.lineWidth = 6;
    ctx.strokeText(text, canvas.width / 2, canvas.height / 2);
    ctx.fillStyle = ORBIT_WISH_PINK;
    ctx.fillText(text, canvas.width / 2, canvas.height / 2);
    const tex = new THREE.CanvasTexture(canvas);
    tex.minFilter = THREE.LinearFilter;
    tex.magFilter = THREE.LinearFilter;
    return tex;
}

function createOrbitingWishSprites() {
    if (orbitingWishGroup) return;
    if (!WISH_SENTENCES || WISH_SENTENCES.length === 0) return;
    orbitingWishGroup = new THREE.Group();
    orbitingWishGroup.visible = true;
    for (let i = 0; i < ORBIT_WISH_COUNT; i++) {
        const text = WISH_SENTENCES[i % WISH_SENTENCES.length];
        const tex = createOrbitingWishTexture(text);
        const mat = new THREE.SpriteMaterial({
            map: tex,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });
        const sprite = new THREE.Sprite(mat);
        sprite.material.opacity = 0; // Báº¯t Ä‘áº§u áº©n, fade-in tá»« tá»« sau
        const aspect = tex.image ? tex.image.width / tex.image.height : 7;
        sprite.scale.set(aspect * 2.2, 2.2, 1);
        sprite.userData.orbitAngle = Math.random() * Math.PI * 2;
        sprite.userData.orbitSpeed = 0.04 + Math.random() * 0.08;
        sprite.userData.orbitRadius = 28 + Math.random() * 40;
        sprite.userData.baseY = (Math.random() - 0.5) * 35;
        sprite.userData.floatSpeed = 0.25 + Math.random() * 0.4;
        sprite.userData.floatAmplitude = 1.5 + Math.random() * 2.5;
        sprite.userData.floatPhase = Math.random() * Math.PI * 2;
        sprite.userData.appearDelay = Math.random() * ORBIT_WISH_APPEAR_SPAN; // Xuáº¥t hiá»‡n ráº£i Ä‘á»u trong 8s
        orbitingWishGroup.add(sprite);
    }
    scene.add(orbitingWishGroup);
    // KhÃ´ng Ä‘Æ°a vÃ o fadeObjects â€” opacity Ä‘iá»u khiá»ƒn riÃªng báº±ng staggered fade-in
}


const positions = [],
    sampleCount = 7e3,
    xs = polyPts.map(t => t.x),
    ys = polyPts.map(t => t.y),
    minX = Math.min(...xs),
    maxX = Math.max(...xs),
    minY = Math.min(...ys),
    maxY = Math.max(...ys),
    threshold = minY + (maxY - minY) / 6;
for (; positions.length / 3 < 7e3;) {
    const t = Math.random() * (maxX - minX) + minX,
        e = Math.random() * (maxY - minY) + minY;
    if (isPointInsidePolygon({
        x: t,
        y: e
    }, polyPts)) {
        let a = 1 / 0;
        for (let o = 0; o < polyPts.length; o++) {
            const s = polyPts[o],
                r = polyPts[(o + 1) % polyPts.length],
                i = r.x - s.x,
                n = r.y - s.y,
                l = ((t - s.x) * i + (e - s.y) * n) / (i * i + n * n),
                m = Math.max(0, Math.min(1, l)),
                c = t - (s.x + m * i),
                p = e - (s.y + m * n),
                d = c * c + p * p;
            d < a && (a = d)
        }
        const o = 1 / (1 + 2 * Math.sqrt(a));
        if (Math.random() < o) {
            const a = 3.6 * (Math.random() - .5);
            positions.push(t - 5, e - 7, a)
        }
    }
}
let minZ = 1 / 0,
    maxZval = -1 / 0;
for (let t = 2; t < positions.length; t += 3) {
    const e = positions[t];
    e < minZ && (minZ = e), e > maxZval && (maxZval = e)
}
const heartDepth = maxZval - minZ,
    heartWidth = maxX - minX,
    planeXVar = 2 * heartWidth,
    rStreamStart = .8 * heartWidth,
    Rmax = rStreamStart,
    rVortex = .6 * heartWidth,
    planeZVar = 15 * heartDepth,
    planeYCenter = maxY,
    planeYVar = 1,
    riseDuration = 10,
    fallDuration = 0,
    holdDuration = 0,
    STREAM_RISE_MIN = 8,
    STREAM_RISE_MAX = 12,
    INDENT_Y = maxY - .25 * (maxY - minY),
    INDENT_HALF_WIDTH = .35 * heartWidth,
    COS_ANGLE_THRESH = .707106,
    CLIP_FRONT_Z = .3,
    staticGeo = new THREE.BufferGeometry,
    originalPositions = positions.slice();
staticGeo.setAttribute("position", new THREE.Float32BufferAttribute(originalPositions, 3));
const colors = [];
for (let t = 0; t < positions.length; t += 3) colors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b);
staticGeo.setAttribute("color", new THREE.Float32BufferAttribute(colors, 3));
const staticSizes = new Float32Array(positions.length / 3),
    SIZE_SCALE = 2;
for (let t = 0; t < staticSizes.length; t++) staticSizes[t] = 2 * (.3 * Math.random() + .2);
staticGeo.setAttribute("size", new THREE.Float32BufferAttribute(staticSizes, 1));
const topIndices = [];
for (let t = 0; t < positions.length; t += 3) positions[t + 1] > threshold + .1 * (Math.random() - .5) * (maxY - minY) && topIndices.push(t / 3);
const topSet = new Set(topIndices);
let bottomPositions = [];
const bottomColors = [],
    bottomSizes = [],
    bottomSizesBase = [],
    topPositionsArr = [],
    topColors = [],
    topSizes = [],
    topAlpha = [],
    idxToTopIdx = new Int32Array(positions.length / 3).fill(-1);
for (let t = 0, e = 0; t < positions.length; t += 3) {
    const a = t / 3,
        o = staticSizes[a],
        s = positions[t],
        r = positions[t + 1],
        i = positions[t + 2];
    if (topSet.has(a)) {
        topPositionsArr.push(s, r, i), topColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), topSizes.push(o);
        const t = Math.abs(s) < INDENT_HALF_WIDTH && r > INDENT_Y;
        topAlpha.push(t ? 0 : 1), idxToTopIdx[a] = e++
    } else bottomPositions.push(s, r, i), bottomColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), bottomSizes.push(o)
}
staticGeo.setAttribute("position", new THREE.Float32BufferAttribute(topPositionsArr, 3)), staticGeo.setAttribute("color", new THREE.Float32BufferAttribute(topColors, 3)), staticGeo.setAttribute("size", new THREE.Float32BufferAttribute(topSizes, 1)), staticGeo.setAttribute("alpha", new THREE.BufferAttribute(new Float32Array(topAlpha), 1)), staticGeo.attributes.position.needsUpdate = !0, staticGeo.attributes.alpha.needsUpdate = !0;
const topCount = topPositionsArr.length / 3,
    topRadiusArr = new Float32Array(topCount),
    topPhaseArr = new Float32Array(topCount),
    topDelayArr = new Float32Array(topCount);
for (let t = 0; t < topCount; t++) {
    const e = topPositionsArr[3 * t],
        a = topPositionsArr[3 * t + 2],
        o = Math.sqrt(e * e + a * a);
    topRadiusArr[t] = o, topPhaseArr[t] = Math.atan2(a, e), topDelayArr[t] = 10 * Math.random()
}
const GLOBAL_SPIRAL_FREQ = .5,
    BASE_OMEGA = -1 * Math.PI / 10,
    GATHER_RATIO = .01,
    HOLD_RATIO = .2,
    radiusPow = 2.5,
    rCore = .25,
    rOuter = rVortex,
    vIn = .9,
    SHRINK_TO_CORE = !1,
    BURST_SPREAD = .1,
    FADE_DURATION = 1.5,
    SPAWN_DELAY_MAX = 3,
    ASCEND_DELAY_MAX = 10,
    apexY = maxY,
    LOW_REGION_FACTOR = .5;
let minBottomY = 1 / 0,
    maxBottomY = -1 / 0;
for (let t = 1; t < bottomPositions.length; t += 3) {
    const e = bottomPositions[t];
    e < minBottomY && (minBottomY = e), e > maxBottomY && (maxBottomY = e)
}
const Y_THRESHOLD = minBottomY + .5 * (maxBottomY - minBottomY),
    HIGH_BOTTOM_MULT = 2;
{
    const t = [],
        e = [],
        a = [];
    for (let o = 0; o < bottomPositions.length; o += 3) {
        const s = bottomPositions[o + 1];
        if (s >= Y_THRESHOLD)
            for (let r = 1; r < 2; r++) t.push(bottomPositions[o], s, bottomPositions[o + 2]), e.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), a.push(bottomSizes[o / 3])
    }
    bottomPositions.push(...t), bottomColors.push(...e), bottomSizes.push(...a)
}
const BOTTOM_ROTATE_RATIO = .2,
    rotPos = [],
    rotColors = [],
    rotSizes = [],
    staticBotPos = [],
    staticBotColors = [],
    staticBotSizes = [];
for (let t = 0; t < bottomPositions.length; t += 3) Math.random() < .2 ? (rotPos.push(bottomPositions[t], bottomPositions[t + 1], bottomPositions[t + 2]), rotColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), rotSizes.push(bottomSizes[t / 3])) : (staticBotPos.push(bottomPositions[t], bottomPositions[t + 1], bottomPositions[t + 2]), staticBotColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), staticBotSizes.push(bottomSizes[t / 3]));
bottomPositions.length = 0, bottomPositions.push(...rotPos), bottomColors.length = 0, bottomColors.push(...rotColors), bottomSizes.length = 0, bottomSizes.push(...rotSizes);
const bottomCount = bottomPositions.length / 3,
    bottomRadiusArr = new Float32Array(bottomCount),
    bottomPhaseArr = new Float32Array(bottomCount),
    bottomDelayArr = new Float32Array(bottomCount),
    CLEFT_FACTOR = 2.5,
    bottomAlphaArr = new Float32Array(bottomCount).fill(1),
    bottomIsLow = new Uint8Array(bottomCount),
    pivotOffset = .25 * heartWidth,
    KEEP_LOW_MIN = 0,
    KEEP_LOW_MAX = .3;
for (let t = 0; t < bottomCount; t++) {
    const e = bottomPositions[3 * t],
        a = bottomPositions[3 * t + 1],
        o = bottomPositions[3 * t + 2],
        s = a < Y_THRESHOLD;
    if (bottomIsLow[t] = s ? 1 : 0, s) {
        const e = 0 + (a - minBottomY) / (Y_THRESHOLD - minBottomY) * .3;
        bottomAlphaArr[t] = Math.random() < e ? 1 : 0
    } else bottomAlphaArr[t] = 1;
    const r = Math.sqrt(e * e + o * o),
        i = Math.atan2(o, e),
        n = Math.min(1, Math.abs(e) / (.25 * heartWidth)),
        l = 1.5 * Math.pow(1 - n, 3) + 1;
    bottomRadiusArr[t] = r * l, bottomPhaseArr[t] = i, bottomDelayArr[t] = 10 * Math.random()
}
const bottomAlphaBase = Float32Array.from(bottomAlphaArr),
    bottomGeo = new THREE.BufferGeometry;

// === HIá»†U á»¨NG GHÃ‰P Háº T THÃ€NH TRÃI TIM ===
// LÆ°u vá»‹ trÃ­ Ä‘Ã­ch (target positions) cá»§a cÃ¡c háº¡t
const topTargetPositions = new Float32Array(topPositionsArr);
const bottomTargetPositions = new Float32Array(bottomPositions);

// Táº¡o vá»‹ trÃ­ ban Ä‘áº§u ngáº«u nhiÃªn cho cÃ¡c háº¡t (táº¥t cáº£ á»Ÿ má»™t Ä‘iá»ƒm hoáº·c ráº£i rÃ¡c)
const HEART_ASSEMBLY_DURATION = 1.1; // Thá»i gian ghÃ©p thÃ nh trÃ¡i tim (ráº¥t nhanh nhÆ°ng váº«n cÃ³ cáº£m giÃ¡c hiá»‡u á»©ng)
let heartAssemblyStart = null;
const SPAWN_RADIUS = 90; // BÃ¡n kÃ­nh vÃ¹ng spawn ban Ä‘áº§u (cho háº¡t gáº§n trung tÃ¢m hÆ¡n ná»¯a Ä‘á»ƒ tháº¥y sá»›m)

// Táº¡o delay array cho má»—i háº¡t Ä‘á»ƒ táº¡o hiá»‡u á»©ng sÃ³ng má»m máº¡i (nhÆ°ng ngáº¯n Ä‘á»ƒ xuáº¥t hiá»‡n nhanh)
const topDelayArray = new Float32Array(topPositionsArr.length / 3);
for (let i = 0; i < topDelayArray.length; i++) {
    topDelayArray[i] = Math.random() * 0.25; // Delay tá»« 0 Ä‘áº¿n 0.25 giÃ¢y
}

const bottomDelayArray = new Float32Array(bottomPositions.length / 3);
for (let i = 0; i < bottomDelayArray.length; i++) {
    bottomDelayArray[i] = Math.random() * 0.25;
}

// Khá»Ÿi táº¡o vá»‹ trÃ­ ban Ä‘áº§u cho top particles (xung quanh má»™t Ä‘iá»ƒm ngáº«u nhiÃªn)
const topStartPositions = new Float32Array(topPositionsArr.length);
for (let i = 0; i < topPositionsArr.length; i += 3) {
    // Táº¡o vá»‹ trÃ­ ngáº«u nhiÃªn trong má»™t hÃ¬nh cáº§u
    const phi = Math.acos((2 * Math.random()) - 1);
    const theta = Math.random() * Math.PI * 2;
    const radius = SPAWN_RADIUS * (0.5 + Math.random() * 0.5);
    
    topStartPositions[i] = radius * Math.sin(phi) * Math.cos(theta);
    topStartPositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
    topStartPositions[i + 2] = radius * Math.cos(phi);
}

// Khá»Ÿi táº¡o vá»‹ trÃ­ ban Ä‘áº§u cho bottom particles
const bottomStartPositions = new Float32Array(bottomPositions.length);
for (let i = 0; i < bottomPositions.length; i += 3) {
    const phi = Math.acos((2 * Math.random()) - 1);
    const theta = Math.random() * Math.PI * 2;
    const radius = SPAWN_RADIUS * (0.5 + Math.random() * 0.5);
    
    bottomStartPositions[i] = radius * Math.sin(phi) * Math.cos(theta);
    bottomStartPositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
    bottomStartPositions[i + 2] = radius * Math.cos(phi);
}

// Äáº·t vá»‹ trÃ­ ban Ä‘áº§u cho cÃ¡c geometries
staticGeo.attributes.position.array.set(topStartPositions);
staticGeo.attributes.position.needsUpdate = true;

bottomGeo.setAttribute("position", new THREE.Float32BufferAttribute(bottomStartPositions, 3)), bottomGeo.setAttribute("color", new THREE.Float32BufferAttribute(bottomColors, 3).setUsage(THREE.DynamicDrawUsage)), bottomGeo.setAttribute("size", new THREE.Float32BufferAttribute(bottomSizes, 1)), bottomGeo.setAttribute("alpha", new THREE.BufferAttribute(bottomAlphaArr, 1));
// === Káº¾T THÃšC PHáº¦N KHá»žI Táº O BAN Äáº¦U ===
const V_SLOPE = .3,
    matBottom = makeMat({
        map: circleTexture,
        alphaSupport: !0,
        vClipSlope: .3,
        clipFrontZ: .3
    });
matBottom.alphaTest = .5;
const bottomHeart = new THREE.Points(bottomGeo, matBottom);
bottomHeart.rotation.z = Math.PI, bottomHeart.renderOrder = 0, scene.add(bottomHeart);

const BOTTOM_OMEGA = BASE_OMEGA,
    topPointVisibility = new Array(topIndices.length).fill(!0);
let hiddenTopCount = 0;
const matStatic = makeMat({
    map: circleTexture,
    alphaSupport: !0
});
matStatic.alphaTest = .5;
const staticHeart = new THREE.Points(staticGeo, matStatic);
staticHeart.rotation.z = Math.PI, staticHeart.renderOrder = 0, scene.add(staticHeart);
const TOP_STATIC_RATIO = .5;
{
    const t = [],
        e = [],
        a = [];
    for (let o = 0; o < topPositionsArr.length; o += 3) {
        const s = calculateMinimumDistanceToBorder(topPositionsArr[o] + 5, topPositionsArr[o + 1] + 7) < BORDER_THRESHOLD || Math.random() < .3;
        Math.random() < .5 && s && (t.push(topPositionsArr[o], topPositionsArr[o + 1], topPositionsArr[o + 2]), e.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), a.push(topSizes[Math.floor(o / 3)]))
    }
    if (t.length) {
        const o = new THREE.BufferGeometry;
        o.setAttribute("position", new THREE.Float32BufferAttribute(t, 3)), o.setAttribute("color", new THREE.Float32BufferAttribute(e, 3).setUsage(THREE.DynamicDrawUsage)), o.setAttribute("size", new THREE.Float32BufferAttribute(a, 1));
        const s = makeMat({
            map: circleTexture,
            alphaSupport: !0
        });
        s.alphaTest = .5, staticTopHeart = new THREE.Points(o, s), staticTopHeart.rotation.z = Math.PI, staticTopHeart.renderOrder = 0, scene.add(staticTopHeart);
        
        // LÆ°u vá»‹ trÃ­ Ä‘Ã­ch vÃ  táº¡o vá»‹ trÃ­ ban Ä‘áº§u cho staticTopHeart
        const staticTopTargetPositions = new Float32Array(staticTopHeart.geometry.attributes.position.array);
        const staticTopStartPositions = new Float32Array(staticTopTargetPositions.length);
        const staticTopDelayArray = new Float32Array(staticTopTargetPositions.length / 3);
        for (let i = 0; i < staticTopTargetPositions.length; i += 3) {
            const phi = Math.acos((2 * Math.random()) - 1);
            const theta = Math.random() * Math.PI * 2;
            const radius = SPAWN_RADIUS * (0.5 + Math.random() * 0.5);
            
            staticTopStartPositions[i] = radius * Math.sin(phi) * Math.cos(theta);
            staticTopStartPositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
            staticTopStartPositions[i + 2] = radius * Math.cos(phi);
            
            staticTopDelayArray[i / 3] = Math.random() * 0.8;
        }
        staticTopHeart.geometry.attributes.position.array.set(staticTopStartPositions);
        staticTopHeart.geometry.attributes.position.needsUpdate = true;
        staticTopHeart.userData.targetPositions = staticTopTargetPositions;
        staticTopHeart.userData.startPositions = staticTopStartPositions;
        staticTopHeart.userData.delayArray = staticTopDelayArray;
    }
}
if (staticBotPos.length > 0) {
    const t = new THREE.BufferGeometry;
    t.setAttribute("position", new THREE.Float32BufferAttribute(staticBotPos, 3)), t.setAttribute("color", new THREE.Float32BufferAttribute(staticBotColors, 3).setUsage(THREE.DynamicDrawUsage)), t.setAttribute("size", new THREE.Float32BufferAttribute(staticBotSizes, 1));
    const e = makeMat({
        map: circleTexture,
        alphaSupport: !0
    });
    e.alphaTest = .5, staticBottomHeart = new THREE.Points(t, e), staticBottomHeart.rotation.z = Math.PI, staticBottomHeart.renderOrder = 0, scene.add(staticBottomHeart);
    
    // LÆ°u vá»‹ trÃ­ Ä‘Ã­ch vÃ  táº¡o vá»‹ trÃ­ ban Ä‘áº§u cho staticBottomHeart
    const staticBottomTargetPositions = new Float32Array(staticBottomHeart.geometry.attributes.position.array);
    const staticBottomStartPositions = new Float32Array(staticBottomTargetPositions.length);
    const staticBottomDelayArray = new Float32Array(staticBottomTargetPositions.length / 3);
    for (let i = 0; i < staticBottomTargetPositions.length; i += 3) {
        const phi = Math.acos((2 * Math.random()) - 1);
        const theta = Math.random() * Math.PI * 2;
        const radius = SPAWN_RADIUS * (0.5 + Math.random() * 0.5);
        
        staticBottomStartPositions[i] = radius * Math.sin(phi) * Math.cos(theta);
        staticBottomStartPositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
        staticBottomStartPositions[i + 2] = radius * Math.cos(phi);
        
        staticBottomDelayArray[i / 3] = Math.random() * 0.8;
    }
    staticBottomHeart.geometry.attributes.position.array.set(staticBottomStartPositions);
    staticBottomHeart.geometry.attributes.position.needsUpdate = true;
    staticBottomHeart.userData.targetPositions = staticBottomTargetPositions;
    staticBottomHeart.userData.startPositions = staticBottomStartPositions;
    staticBottomHeart.userData.delayArray = staticBottomDelayArray;
}
const SPAWN_MULT = .2,
    rimIndices = [];
for (const t of topIndices) calculateMinimumDistanceToBorder(positions[3 * t], positions[3 * t + 1]) < BORDER_THRESHOLD && rimIndices.push(t);
const streamSource = rimIndices.length ? rimIndices : topIndices,
    streamCount = Math.floor(.2 * streamSource.length),
    targetIdxArr = new Uint32Array(streamCount);
for (let t = 0; t < streamCount; t++) targetIdxArr[t] = streamSource[t % streamSource.length];
const planeIdxForStream = new Int32Array(streamCount).fill(-1),
    streamPositions = new Float32Array(3 * streamCount),
    streamGeo = new THREE.BufferGeometry,
    streamAlpha = new Float32Array(streamCount).fill(1);
streamGeo.setAttribute("alpha", new THREE.BufferAttribute(streamAlpha, 1)), streamGeo.setAttribute("position", new THREE.BufferAttribute(streamPositions, 3).setUsage(THREE.DynamicDrawUsage));
const streamColors = new Float32Array(3 * streamCount);
for (let t = 0; t < streamCount; t++) {
    streamColors[3 * t] = heartInitialColor.r;
    streamColors[3 * t + 1] = heartInitialColor.g;
    streamColors[3 * t + 2] = heartInitialColor.b;
}
streamGeo.setAttribute("color", new THREE.BufferAttribute(streamColors, 3));
const streamSizes = new Float32Array(streamCount);
for (let t = 0; t < streamCount; t++) streamSizes[t] = 2 * (.3 * Math.random() + .2 + .1) * 1.5;
const streamSizeBase = streamSizes.slice(),
    BIG_RATIO = .1;
for (let t = 0; t < streamCount; t++) {
    if (Math.random() < .1) {
        streamSizes[t] *= 1.5;
        streamColors[3 * t] = heartInitialColor.r;
        streamColors[3 * t + 1] = heartInitialColor.g;
        streamColors[3 * t + 2] = heartInitialColor.b;
    }
}
streamGeo.setAttribute("size", new THREE.BufferAttribute(streamSizes, 1));
const matStream = makeMat({
    map: circleTexture,
    alphaSupport: !0,
    clipBandWidth: INDENT_HALF_WIDTH,
    clipFrontZ: .3
});
matStream.alphaTest = .5;
const streamHeart = new THREE.Points(streamGeo, matStream);
streamHeart.rotation.z = Math.PI, streamHeart.renderOrder = 1, scene.add(streamHeart), streamHeart.visible = !1, fadeObjects.push(streamHeart), streamHeart.userData.fadeStage = STAGE.STREAM;
// Giáº£m máº­t Ä‘á»™, tÄƒng kÃ­ch thÆ°á»›c Ä‘á»ƒ táº¡o cáº£m giÃ¡c cÃ¡c tia sÃ¡ng dÃ i nhÆ° sao bÄƒng
const PLANE_COUNT = Math.floor(80 * rVortex),
    planePositions = [],
    planeColors = [],
    planeSizes = [],
    planeAlphaArr = new Float32Array(PLANE_COUNT).fill(1);
for (let t = 0; t < PLANE_COUNT; t++) {
    const t = Math.random() * Math.PI * 2,
        e = Math.sqrt(Math.random()) * rVortex;
    // Äáº·t cÃ¡c Ä‘iá»ƒm trÃªn vÃ²ng, nhÆ°ng cho kÃ­ch thÆ°á»›c lá»›n hÆ¡n Ä‘á»ƒ giá»‘ng vá»‡t sÃ¡ng dÃ i
    planePositions.push(Math.cos(t) * e, planeYCenter - 7.5, Math.sin(t) * e),
        planeColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b),
        planeSizes.push(2.5 * Math.random() + 1.5);
}
const planeGeo = new THREE.BufferGeometry;
planeGeo.setAttribute("position", new THREE.Float32BufferAttribute(planePositions, 3)), planeGeo.setAttribute("color", new THREE.Float32BufferAttribute(planeColors, 3)), planeGeo.setAttribute("size", new THREE.Float32BufferAttribute(planeSizes, 1)), planeGeo.setAttribute("alpha", new THREE.BufferAttribute(planeAlphaArr, 1));
const matPlane = makeMat({
    map: circleTexture,
    alphaSupport: !0,
    // DÃ¹ng AdditiveBlending + opacity Ä‘á»ƒ táº¡o hiá»‡u á»©ng sao bÄƒng phÃ¡t sÃ¡ng, cÃ³ vá»‡t
    blending: THREE.AdditiveBlending,
    opacity: 0.85
});
matPlane.alphaTest = .5;
const planeLayer = new THREE.Points(planeGeo, matPlane);
planeLayer.rotation.z = Math.PI, scene.add(planeLayer), fadeObjects.push(planeLayer), fadeObjects.includes(planeLayer) && fadeObjects.splice(fadeObjects.indexOf(planeLayer), 1), planeLayer.visible = !0;

// --- Táº O VIá»€N TÆ¯á»œNG THÃ€NH Báº°NG áº¢NH QUANH ÄÄ¨A QUAY ---
let imageWallGroup = null;
let imageWallMeshes = [];
const roundedWallTextures = [];

function getRoundedWallTexture(idx) {
    if (roundedWallTextures[idx]) return roundedWallTextures[idx];
    const tex = imageTextures[idx];
    if (!tex) return null;
    const rtex = createRoundedImageTextureFromTexture(tex) || tex;
    rtex.flipY = false;
    roundedWallTextures[idx] = rtex;
    return rtex;
}

async function createImageWall() {
    if (!imageLoadingComplete || IMAGE_CONFIG.count === 0) return;
    
    // XÃ³a tÆ°á»ng cÅ© náº¿u cÃ³
    if (imageWallGroup) {
        scene.remove(imageWallGroup);
        imageWallMeshes = [];
    }
    
    imageWallGroup = new THREE.Group();
    const WALL_HEIGHT = 8; // Chiá»u cao cá»§a tÆ°á»ng thÃ nh
    const WALL_RADIUS = rVortex + 0.5; // BÃ¡n kÃ­nh lá»›n hÆ¡n Ä‘Ä©a má»™t chÃºt
    const SEGMENTS = 64; // Sá»‘ cáº¡nh cá»§a hÃ¬nh trá»¥ (cÃ ng nhiá»u cÃ ng má»‹n)
    const IMAGES_PER_WALL = Math.max(4, Math.floor(IMAGE_CONFIG.count / 2)); // Sá»‘ áº£nh trÃªn má»—i táº¥m tÆ°á»ng
    
    // LuÃ´n táº¡o 8 táº¥m tÆ°á»ng
    const WALL_SEGMENTS = 8; // Cá»‘ Ä‘á»‹nh 8 táº¥m tÆ°á»ng
    
    for (let i = 0; i < WALL_SEGMENTS; i++) {
        const angle = (i / WALL_SEGMENTS) * Math.PI * 2;
        
        // Táº¡o má»™t táº¥m tÆ°á»ng (hÃ¬nh chá»¯ nháº­t)
        const wallWidth = (2 * Math.PI * WALL_RADIUS) / WALL_SEGMENTS;
        const wallGeometry = new THREE.PlaneGeometry(wallWidth, WALL_HEIGHT);
        
        // Chá»n áº£nh Ä‘á»ƒ hiá»ƒn thá»‹:
        // - Náº¿u sá»‘ áº£nh <= 8: láº·p láº¡i áº£nh Ä‘á»ƒ Ä‘á»§ 8 táº¥m (vÃ­ dá»¥ 4 áº£nh â†’ má»—i áº£nh láº·p 2 láº§n)
        // - Náº¿u sá»‘ áº£nh > 8: chá»‰ dÃ¹ng 8 áº£nh Ä‘áº§u tiÃªn, má»—i áº£nh 1 láº§n
        const imageIndex = IMAGE_CONFIG.count <= 8 
            ? i % IMAGE_CONFIG.count  // Láº·p láº¡i náº¿u Ã­t áº£nh
            : i;  // DÃ¹ng 8 áº£nh Ä‘áº§u náº¿u nhiá»u áº£nh
        const wallTexture = getRoundedWallTexture(imageIndex);
        
        // Táº¡o material vá»›i texture áº£nh
        const wallMaterial = new THREE.MeshBasicMaterial({
            map: wallTexture,
            transparent: true,
            side: THREE.DoubleSide,
            opacity: 1.0 // TÄƒng lÃªn 1.0 Ä‘á»ƒ áº£nh rÃµ hÆ¡n
        });
        
        const wallMesh = new THREE.Mesh(wallGeometry, wallMaterial);
        
        // Äáº·t vá»‹ trÃ­ táº¥m tÆ°á»ng
        wallMesh.position.x = Math.cos(angle) * WALL_RADIUS;
        wallMesh.position.y = planeYCenter - 7.5; // CÃ¹ng Ä‘á»™ cao vá»›i Ä‘Ä©a
        wallMesh.position.z = Math.sin(angle) * WALL_RADIUS;
        
        // Xoay táº¥m tÆ°á»ng Ä‘á»ƒ hÆ°á»›ng ra ngoÃ i
        wallMesh.lookAt(
            Math.cos(angle) * (WALL_RADIUS + 1),
            planeYCenter - 7.5,
            Math.sin(angle) * (WALL_RADIUS + 1)
        );
        
        // Xoay thÃªm 180 Ä‘á»™ quanh trá»¥c Y Ä‘á»ƒ láº­t áº£nh
        wallMesh.rotateY(Math.PI);
        
        imageWallGroup.add(wallMesh);
        imageWallMeshes.push(wallMesh);
    }
    
    scene.add(imageWallGroup);
    imageWallGroup.rotation.z = Math.PI; // CÃ¹ng rotation vá»›i planeLayer
    
    // ThÃªm vÃ o fadeObjects Ä‘á»ƒ fade in cÃ¹ng vá»›i cÃ¡c Ä‘á»‘i tÆ°á»£ng khÃ¡c
    imageWallGroup.visible = true;
    imageWallGroup.userData.fadeStage = STAGE.STREAM; // Fade in cÃ¹ng lÃºc vá»›i stream
    fadeObjects.push(imageWallGroup);
    
    // Äáº·t opacity ban Ä‘áº§u = 0 Ä‘á»ƒ fade in (trá»« khi fade Ä‘Ã£ xong â€” táº¡o tÆ°á»ng trá»… do load áº£nh)
    imageWallMeshes.forEach(mesh => {
        if (mesh.material) {
            mesh.userData.baseOpacity = 1.0;
            mesh.material.opacity = revealStart === null ? 1.0 : 0;
        }
    });
    // Náº¿u tÆ°á»ng Ä‘Æ°á»£c táº¡o sau khi giai Ä‘oáº¡n fade Ä‘Ã£ káº¿t thÃºc, hiá»‡n luÃ´n 8 áº£nh
    if (revealStart === null) {
        imageWallMeshes.forEach(mesh => {
            if (mesh.material) mesh.material.opacity = 1;
        });
    }
}

// --- áº¢NH BAY RA Tá»ª TRUNG TÃ‚M & LÆ  Lá»¬NG ---
const IMAGE_BURST_COUNT = 30;
const IMAGE_BURST_FLY_DURATION = 4.0; // Thá»i gian bay ra (tÄƒng lÃªn Ä‘á»ƒ má»m máº¡i hÆ¡n)
const IMAGE_BURST_DELAY = 0.08; // Delay giá»¯a cÃ¡c áº£nh (tÄƒng lÃªn Ä‘á»ƒ táº¡o hiá»‡u á»©ng sÃ³ng má»m máº¡i hÆ¡n)
const IMAGE_BURST_SCALE = 6.0; // KÃ­ch thÆ°á»›c sprite áº£nh nhá» (tÄƒng máº¡nh cho rÃµ hÆ¡n)
const IMAGE_BURST_FLOAT_AMPLITUDE = { min: 1.5, max: 3.5 };
const IMAGE_BURST_FLOAT_SPEED = { min: 0.6, max: 1.2 };
const IMAGE_BURST_ORBIT_RADIUS = { min: 2.5, max: 5 };
const IMAGE_BURST_ORBIT_SPEED = { min: 0.25, max: 0.55 };
let imageBurstSprites = [];
let imageBurstStarted = false;
let imageBurstStartTime = null;

// Táº¡o texture bo gÃ³c nháº¹ tá»« texture áº£nh gá»‘c (an toÃ n, trÃ¡nh lá»—i Ä‘Ä©a quay bá»‹ Ä‘en)
function createRoundedImageTextureFromTexture(tex) {
    if (!tex || !tex.image) return tex;
    const img = tex.image;

    // Náº¿u áº£nh chÆ°a load xong hoáº·c khÃ´ng pháº£i HTMLImageElement, giá»¯ nguyÃªn texture gá»‘c
    if (!(img instanceof HTMLImageElement) || !img.complete || !img.naturalWidth || !img.naturalHeight) {
        return tex;
    }

    const w = img.naturalWidth || img.width || 512;
    const h = img.naturalHeight || img.height || 512;

    try {
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d");
        if (!ctx) return tex;

        const radius = Math.min(w, h) * 0.18; // bo gÃ³c ~18%

        function roundRect(ctx, x, y, width, height, r) {
            ctx.beginPath();
            ctx.moveTo(x + r, y);
            ctx.lineTo(x + width - r, y);
            ctx.quadraticCurveTo(x + width, y, x + width, y + r);
            ctx.lineTo(x + width, y + height - r);
            ctx.quadraticCurveTo(x + width, y + height, x + width - r, y + height);
            ctx.lineTo(x + r, y + height);
            ctx.quadraticCurveTo(x, y + height, x, y + height - r);
            ctx.lineTo(x, y + r);
            ctx.quadraticCurveTo(x, y, x + r, y);
            ctx.closePath();
        }

        ctx.clearRect(0, 0, w, h);
        ctx.save();
        roundRect(ctx, 0, 0, w, h, radius);
        ctx.clip();
        ctx.drawImage(img, 0, 0, w, h);
        ctx.restore();

        const roundedTex = new THREE.CanvasTexture(canvas);
        roundedTex.minFilter = tex.minFilter || THREE.LinearFilter;
        roundedTex.magFilter = tex.magFilter || THREE.LinearFilter;
        roundedTex.needsUpdate = true;
        return roundedTex;
    } catch (err) {
        // Náº¿u cÃ³ lá»—i (vÃ­ dá»¥ CORS khi dÃ¹ng áº£nh ngoÃ i domain), quay láº¡i dÃ¹ng texture gá»‘c Ä‘á»ƒ khÃ´ng bá»‹ khá»‘i Ä‘en
        console.warn("Rounded texture creation failed, fallback to original texture:", err);
        return tex;
    }
}
function startImageBurst(currentTime) {
    if (!imageLoadingComplete || IMAGE_CONFIG.count === 0) return;
    imageBurstSprites = [];
    imageBurstStartTime = currentTime;
    imageBurstStarted = true;
    // Boost quay nhanh ngáº¯n
    spinBoostUntil = currentTime + 1.0;
    for (let i = 0; i < IMAGE_BURST_COUNT; i++) {
        const tex = imageTextures[i % IMAGE_CONFIG.count];
        const spr = createImageBurstSprite(tex, i);
        if (spr) imageBurstSprites.push(spr);
    }
}

function createImageBurstSprite(tex, idx) {
    if (!tex) return null;
    const roundedTex = createRoundedImageTextureFromTexture(tex) || tex;
    const aspect = getAspectRatioAdjustedScale(roundedTex, IMAGE_BURST_SCALE);
    const mat = buildImageSpriteMaterial(roundedTex, 0);
    const sprite = new THREE.Sprite(mat);
    // TÄƒng chiá»u cao, giáº£m chiá»u rá»™ng (Ä‘iá»u chá»‰nh: rá»™ng hÆ¡n má»™t chÃºt)
    sprite.scale.set(aspect.x * 0.85, aspect.y * 1.4, 1);
    // Láº­t ngÆ°á»£c áº£nh theo chiá»u dá»c náº¿u Ä‘ang bá»‹ Ãºp (flip vertical)
    sprite.scale.y *= -1;

    // Start táº¡i tÃ¢m trÃ¡i tim lá»›n
    const startPos = { x: 0, y: 10, z: 0 };
    sprite.position.set(startPos.x, startPos.y, startPos.z);

    // Target ngáº«u nhiÃªn xung quanh
    const angle = (idx / IMAGE_BURST_COUNT) * Math.PI * 2 + Math.random() * 0.5;
    const radius = 40 + Math.random() * 25; // 40-65
    const height = -20 + Math.random() * 60; // -20..40
    const targetPos = {
        x: Math.cos(angle) * radius,
        y: height,
        z: Math.sin(angle) * radius
    };

    sprite.userData.startPosition = startPos;
    sprite.userData.targetPosition = targetPos;
    sprite.userData.startTime = null;
    sprite.userData.delay = idx * IMAGE_BURST_DELAY;
    sprite.userData.hasReachedTarget = false;

    // Thuá»™c tÃ­nh lÆ¡ lá»­ng khi Ä‘Ã£ Ä‘áº¿n
    sprite.userData.floatSpeed = IMAGE_BURST_FLOAT_SPEED.min + Math.random() * (IMAGE_BURST_FLOAT_SPEED.max - IMAGE_BURST_FLOAT_SPEED.min);
    sprite.userData.floatAmplitude = IMAGE_BURST_FLOAT_AMPLITUDE.min + Math.random() * (IMAGE_BURST_FLOAT_AMPLITUDE.max - IMAGE_BURST_FLOAT_AMPLITUDE.min);
    sprite.userData.floatPhase = Math.random() * Math.PI * 2;
    sprite.userData.orbitSpeed = IMAGE_BURST_ORBIT_SPEED.min + Math.random() * (IMAGE_BURST_ORBIT_SPEED.max - IMAGE_BURST_ORBIT_SPEED.min);
    sprite.userData.orbitRadius = IMAGE_BURST_ORBIT_RADIUS.min + Math.random() * (IMAGE_BURST_ORBIT_RADIUS.max - IMAGE_BURST_ORBIT_RADIUS.min);
    sprite.userData.orbitPhase = Math.random() * Math.PI * 2;

    sprite.material.opacity = 0;
    scene.add(sprite);
    return sprite;
}

// Táº¡o tÆ°á»ng thÃ nh sau khi áº£nh Ä‘Ã£ load xong
// Sá»­ dá»¥ng má»™t hÃ m helper Ä‘á»ƒ kiá»ƒm tra vÃ  táº¡o tÆ°á»ng thÃ nh
function tryCreateImageWall() {
    if (imageLoadingComplete && IMAGE_CONFIG.count > 0) {
        createImageWall();
    } else {
        // Náº¿u chÆ°a load xong, thá»­ láº¡i sau
        setTimeout(tryCreateImageWall, 100);
    }
}
tryCreateImageWall();

const PLANE_COLOR_CYCLE = 9,
    PLANE_COL_WHITE = new THREE.Color("rgb(255, 227, 249)"),
    PLANE_COL_LIGHT = new THREE.Color("rgb(255,192,215)"),
    PLANE_COL_DARK = new THREE.Color("rgb(241, 121, 185)");

function createTextSpriteTexture(t) {
    // Tráº£ vá» texture trá»‘ng Ä‘á»ƒ khÃ´ng hiá»ƒn thá»‹ chá»¯ trÃªn Ä‘Ä©a/ring
    const e = document.createElement("canvas");
    e.width = e.height = 128;
    const o = new THREE.CanvasTexture(e);
    return o.minFilter = o.magFilter = THREE.LinearFilter, o
}
planeGeo.attributes.color.setUsage(THREE.DynamicDrawUsage);
const ringCharsFull = RingText.join(""),
    ringChars = Array.from(ringCharsFull),
    charMatMap = {};

function generateTextRingTexture(t) {
    // Tráº£ vá» texture trong suá»‘t Ä‘á»ƒ loáº¡i bá» chá»¯ trÃªn vÃ²ng/Ä‘Ä©a quay
    const e = document.createElement("canvas");
    e.width = 2048; e.height = 256;
    const a = e.getContext("2d");
    a.clearRect(0, 0, e.width, e.height);
    const s = new THREE.CanvasTexture(e);
    s.needsUpdate = true;
    return s;
}

[...new Set(ringChars)].forEach(t => {
    charMatMap[t] = new THREE.SpriteMaterial({
        map: createTextSpriteTexture(t),
        transparent: !0,
        depthWrite: !1
    })
});
const ringTexture = generateTextRingTexture(RingText),
    ringMat = new THREE.MeshBasicMaterial({
        map: ringTexture,
        transparent: !0,
        side: THREE.DoubleSide,
        depthWrite: !1,
        blending: THREE.AdditiveBlending
    }),
    RING_THICKNESS = 3.5,
    RING_HUE_SPEED = .05,
    RING_FADE_DIST = 1,
    RING_FADE_SPEED = 2,
    ringHeight = .8,
    RING_Y_OFFSET = 2 * -planeYCenter - .5,
    ringGeo = new THREE.CylinderGeometry(rVortex, rVortex, 1, 128, 1, !0),
    RING_SPACING = 2,
    RING_START_RADIUS = rVortex,
    RING_END_RADIUS = .25,
    RING_COUNT = Math.ceil((RING_START_RADIUS - .25) / 2),
    RING_FLIP_Y = Math.PI,
    ribbon = new THREE.Group;
ribbon.position.set(0, planeYCenter + RING_Y_OFFSET, 0), ribbon.rotation.z = Math.PI, scene.add(ribbon), ribbon.visible = !0;
for (let t = 0; t < RING_COUNT; t++) {
    const e = generateTextRingTexture([RingText[t % RingText.length]]);
    e.wrapS = THREE.RepeatWrapping, e.repeat.set(2, 1), e.offset.x = 1;
    const a = new THREE.MeshBasicMaterial({
        map: e,
        transparent: !0,
        side: THREE.DoubleSide,
        depthWrite: !1,
        blending: THREE.AdditiveBlending
    }),
        o = new THREE.Mesh(ringGeo, a);
    o.rotation.x = Math.PI;
    const s = RING_START_RADIUS - 2 * t,
        r = 2 * (Math.random() - .5) * .3;
    o.userData.radius = s + r, o.userData.phase = Math.random() * Math.PI * 2;
    const i = s / RING_START_RADIUS;
    o.scale.set(i, 3.5, i), o.material.opacity = 1, o.material.transparent = !0, o.material.depthWrite = !1, o.renderOrder = t, ribbon.add(o)
}
const vortexIndices = [];
for (let t = 0; t < positions.length / 3; t++) topIndices.includes(t) || vortexIndices.push(t);
const vortexCount = vortexIndices.length,
    vortexPositions = new Float32Array(3 * vortexCount),
    vortexPhase = new Float32Array(vortexCount),
    vortexRadius = new Float32Array(vortexCount);
for (let t = 0; t < vortexCount; t++) {
    vortexPhase[t] = Math.random() * Math.PI * 2;
    const e = Math.random() * rVortex;
    vortexRadius[t] = e, vortexPositions[3 * t] = Math.cos(vortexPhase[t]) * e, vortexPositions[3 * t + 1] = planeYCenter, vortexPositions[3 * t + 2] = Math.sin(vortexPhase[t]) * e
}
const vortexGeo = new THREE.BufferGeometry;
vortexGeo.setAttribute("position", new THREE.BufferAttribute(vortexPositions, 3).setUsage(THREE.DynamicDrawUsage));
const vortexColors = new Float32Array(3 * vortexCount);
for (let t = 0; t < vortexCount; t++) vortexColors[3 * t] = heartInitialColor.r, vortexColors[3 * t + 1] = heartInitialColor.g, vortexColors[3 * t + 2] = heartInitialColor.b;
vortexGeo.setAttribute("color", new THREE.BufferAttribute(vortexColors, 3));
const vortexSizes = new Float32Array(vortexCount);
for (let t = 0; t < vortexCount; t++) vortexSizes[t] = .2 * Math.random() + .15;
vortexGeo.setAttribute("size", new THREE.BufferAttribute(vortexSizes, 1));
const vortexMat = makeMat({
    map: circleTexture,
    blending: THREE.AdditiveBlending,
    opacity: .8
});
vortexMat.onBeforeCompile = function (t) {
    t.vertexShader = t.vertexShader.replace("uniform float size;", "attribute float size;")
};
const heartLayers = [staticHeart, bottomHeart, staticBottomHeart, staticTopHeart];
heartLayers.forEach(t => {
    t && (scene.remove(t), heartScene.add(t))
}), heartLayers.forEach(t => {
    t && (t.visible = !1, t.userData.fadeStage = STAGE.HEART, fadeObjects.includes(t) || fadeObjects.push(t))
});
const HEART_OFFSET_Y = 10;
[staticHeart, bottomHeart, staticTopHeart, staticBottomHeart].forEach(t => {
    t && (t.position.y += 10)
});
const HEART_OFFSET_YY = 8;
[streamHeart, ribbon].forEach(t => {
    t && (t.position.y += 8)
});

// === Táº O NHIá»€U TRÃI TIM MINI ===
// Giáº£m sá»‘ lÆ°á»£ng Ä‘á»ƒ nháº¹ hÆ¡n khi khá»Ÿi Ä‘á»™ng
const MINI_HEART_COUNT = 12; // Ãt trÃ¡i tim mini hÆ¡n Ä‘á»ƒ giáº£m sá»‘ háº¡t
const MINI_HEART_SCALE = 0.2; // Tá»· lá»‡ scale (20% kÃ­ch thÆ°á»›c trÃ¡i tim lá»›n - tÄƒng lÃªn Ä‘á»ƒ rÃµ hÆ¡n)
const MINI_HEART_PARTICLE_COUNT = Math.floor(2500 * 0.25); // Giáº£m sá»‘ particles trÃªn má»—i trÃ¡i tim mini Ä‘á»ƒ khá»Ÿi Ä‘á»™ng nhanh hÆ¡n
const miniHearts = [];

function createMiniHeart(scale, position, rotation) {
    // Táº¡o positions cho trÃ¡i tim mini (scale down tá»« trÃ¡i tim lá»›n)
    const miniPositions = [];
    const miniScale = scale;
    
    // Sá»­ dá»¥ng cÃ¹ng heartShape nhÆ°ng scale nhá» hÆ¡n
    for (let i = 0; miniPositions.length / 3 < MINI_HEART_PARTICLE_COUNT; i++) {
        const t = Math.random() * (maxX - minX) + minX,
            e = Math.random() * (maxY - minY) + minY;
        if (isPointInsidePolygon({ x: t, y: e }, polyPts)) {
            let a = 1 / 0;
            for (let o = 0; o < polyPts.length; o++) {
                const s = polyPts[o],
                    r = polyPts[(o + 1) % polyPts.length],
                    i = r.x - s.x,
                    n = r.y - s.y,
                    l = ((t - s.x) * i + (e - s.y) * n) / (i * i + n * n),
                    m = Math.max(0, Math.min(1, l)),
                    c = t - (s.x + m * i),
                    p = e - (s.y + m * n),
                    d = c * c + p * p;
                d < a && (a = d);
            }
            const o = 1 / (1 + 2 * Math.sqrt(a));
            if (Math.random() < o) {
                const a = 3.6 * (Math.random() - .5);
                // Scale down positions
                miniPositions.push((t - 5) * miniScale, (e - 7) * miniScale, a * miniScale);
            }
        }
    }
    
    // Táº¡o geometry vÃ  material
    const miniGeo = new THREE.BufferGeometry();
    miniGeo.setAttribute("position", new THREE.Float32BufferAttribute(miniPositions, 3));
    
    const miniColors = [];
    for (let i = 0; i < miniPositions.length; i += 3) {
        miniColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b);
    }
    miniGeo.setAttribute("color", new THREE.Float32BufferAttribute(miniColors, 3));
    
    const miniSizes = new Float32Array(miniPositions.length / 3);
    for (let i = 0; i < miniSizes.length; i++) {
        // TÄƒng kÃ­ch thÆ°á»›c particles Ä‘á»ƒ rÃµ hÆ¡n (nhÃ¢n thÃªm 1.5)
        miniSizes[i] = 2 * (.3 * Math.random() + .2) * miniScale * 1.5;
    }
    miniGeo.setAttribute("size", new THREE.Float32BufferAttribute(miniSizes, 1));
    
    const miniMat = makeMat({
        map: circleTexture,
        alphaSupport: true
    });
    miniMat.alphaTest = 0.5;
    
    const miniHeart = new THREE.Points(miniGeo, miniMat);
    miniHeart.rotation.z = Math.PI; // Giá»‘ng trÃ¡i tim lá»›n
    miniHeart.position.set(position.x, position.y, position.z);
    // KhÃ´ng quay, Ä‘á»©ng yÃªn nhÆ° trÃ¡i tim lá»›n
    miniHeart.rotation.y = 0;
    miniHeart.rotation.x = 0;
    
    scene.add(miniHeart);
    return miniHeart;
}

// Táº¡o cÃ¡c trÃ¡i tim mini á»Ÿ cÃ¡c vá»‹ trÃ­ cá»‘ Ä‘á»‹nh trong khÃ´ng gian
// PhÃ¢n bá»‘ Ä‘á»u theo cáº£ chiá»u ngang vÃ  chiá»u dá»c
for (let i = 0; i < MINI_HEART_COUNT; i++) {
    // PhÃ¢n bá»‘ Ä‘á»u theo vÃ²ng trÃ²n ngang
    const angle = (i / MINI_HEART_COUNT) * Math.PI * 2;
    const radius = 40 + Math.random() * 20; // Khoáº£ng cÃ¡ch tá»« trung tÃ¢m
    
    // PhÃ¢n bá»‘ Ä‘á»u theo chiá»u dá»c tá»« Ä‘Ã¡y Ä‘áº¿n trÃªn cÃ¹ng
    // Chia thÃ nh cÃ¡c táº§ng: Ä‘Ã¡y, giá»¯a dÆ°á»›i, giá»¯a, giá»¯a trÃªn, trÃªn cÃ¹ng
    const verticalLayer = i % 5; // 5 táº§ng
    const layerProgress = verticalLayer / 4; // 0 (Ä‘Ã¡y) Ä‘áº¿n 1 (trÃªn cÃ¹ng)
    const baseHeight = -30; // Äá»™ cao Ä‘Ã¡y
    const topHeight = 50; // Äá»™ cao trÃªn cÃ¹ng
    const height = baseHeight + (topHeight - baseHeight) * layerProgress;
    
    // ThÃªm má»™t chÃºt ngáº«u nhiÃªn Ä‘á»ƒ khÃ´ng quÃ¡ Ä‘á»u
    const randomOffset = (Math.random() - 0.5) * 10;
    
    const position = {
        x: Math.cos(angle) * radius,
        y: height + randomOffset,
        z: Math.sin(angle) * radius
    };
    
    const rotation = {
        y: 0,
        x: 0
    };
    
    // Vá»‹ trÃ­ ban Ä‘áº§u: á»Ÿ trung tÃ¢m trÃ¡i tim lá»›n (sáº½ bay ra ngoÃ i)
    const startPosition = { x: 0, y: 10, z: 0 }; // Vá»‹ trÃ­ trÃ¡i tim lá»›n
    
    const miniHeart = createMiniHeart(MINI_HEART_SCALE, startPosition, rotation);
    // áº¨n ban Ä‘áº§u, sáº½ fade in sau khi trÃ¡i tim lá»›n hoÃ n thÃ nh
    miniHeart.material.opacity = 0;
    
    // LÆ°u vá»‹ trÃ­ Ä‘Ã­ch (nÆ¡i trÃ¡i tim sáº½ bay Ä‘áº¿n) vÃ  thÃ´ng tin animation
    miniHeart.userData.targetPosition = { x: position.x, y: position.y, z: position.z };
    miniHeart.userData.startPosition = startPosition;
    miniHeart.userData.floatSpeed = 0.6 + Math.random() * 0.6; // Tá»‘c Ä‘á»™ bay lÆ°á»£n (tÄƒng tá»« 0.3-0.7 lÃªn 0.6-1.2)
    miniHeart.userData.floatAmplitude = 2 + Math.random() * 3; // BiÃªn Ä‘á»™ bay lÆ°á»£n (2-5)
    miniHeart.userData.floatPhase = Math.random() * Math.PI * 2; // Phase ngáº«u nhiÃªn
    miniHeart.userData.orbitSpeed = 0.2 + Math.random() * 0.3; // Tá»‘c Ä‘á»™ quay quanh (tÄƒng tá»« 0.1-0.25 lÃªn 0.2-0.5)
    miniHeart.userData.orbitRadius = 3 + Math.random() * 5; // BÃ¡n kÃ­nh quá»¹ Ä‘áº¡o (3-8)
    miniHeart.userData.orbitPhase = Math.random() * Math.PI * 2; // Phase quá»¹ Ä‘áº¡o
    miniHeart.userData.hasReachedTarget = false; // ÄÃ¡nh dáº¥u Ä‘Ã£ Ä‘áº¿n vá»‹ trÃ­ Ä‘Ã­ch chÆ°a
    
    miniHearts.push(miniHeart);
}
// === Káº¾T THÃšC Táº O TRÃI TIM MINI ===

// Biáº¿n Ä‘á»ƒ track fade in cá»§a cÃ¡c trÃ¡i tim mini
let miniHeartsFadeStart = null;
const MINI_HEARTS_FADE_DURATION = 1.2; // Thá»i gian fade in (giáº£m tá»« 2.0 xuá»‘ng 1.2 giÃ¢y Ä‘á»ƒ nhanh hÆ¡n)
const MINI_HEARTS_FLY_OUT_DURATION = 2.5; // Thá»i gian bay tá»« trung tÃ¢m ra ngoÃ i (2.5 giÃ¢y)

const ENABLE_EXPLOSION = !1;
let expPositions, expVelocities, expBirth, expGeo, expColors, expMat, explosionPoints, MAX_EXP, expCount = 0;
const startTimes = new Float32Array(streamCount),
    STATE_ON_DISK = 0,
    STATE_ASCEND = 1,
    streamState = new Uint8Array(streamCount),
    curRadiusArr = new Float32Array(streamCount),
    ascendStart = new Float32Array(streamCount),
    spiralPhase = new Float32Array(streamCount),
    streamRadius = new Float32Array(streamCount),
    initialRadius = new Float32Array(streamCount),
    spiralFrequency = new Float32Array(streamCount),
    spiralDirection = new Float32Array(streamCount),
    extraRotArr = new Float32Array(streamCount),
    MAX_TOP_HIDE = Math.floor(1 * topIndices.length),
    HIDE_DISTANCE = .25,
    TOP_ROT_SPEED = .5,
    streamRiseDuration = new Float32Array(streamCount),
    streamOffsets = new Float32Array(3 * streamCount);
for (let t = 0; t < streamCount; t++) {
    const e = 3 * t,
        a = Math.random() * Math.PI * 2,
        o = Math.acos(2 * Math.random() - 1),
        s = .4;
    streamOffsets[e] = s * Math.sin(o) * Math.cos(a), streamOffsets[e + 1] = s * Math.sin(o) * Math.sin(a), streamOffsets[e + 2] = s * Math.cos(o)
}

function initializeStreamParticleState(t, e) {
    const a = 3 * t,
        o = targetIdxArr[t];
    let s = -1;
    for (let t = 0; t < 100; t++) {
        const t = Math.floor(Math.random() * PLANE_COUNT),
            e = planePositions[3 * t],
            a = planePositions[3 * t + 2];
        if (Math.hypot(e, a) <= .26) {
            s = t;
            break
        }
    } - 1 === s && (s = Math.floor(Math.random() * PLANE_COUNT)), planeIdxForStream[t] = s;
    const r = Math.random() * Math.PI * 2;
    planePositions[3 * s] = Math.cos(r) * rOuter, planePositions[3 * s + 2] = Math.sin(r) * rOuter, planeGeo.attributes.position.needsUpdate = !0;
    const i = planeLayer.rotation.y,
        n = Math.cos(i),
        l = Math.sin(i),
        m = n * planePositions[3 * s] - l * planePositions[3 * s + 2],
        c = l * planePositions[3 * s] + n * planePositions[3 * s + 2];
    streamPositions[a] = m, streamPositions[a + 1] = planePositions[3 * s + 1], streamPositions[a + 2] = c;
    const p = .25 + (rOuter - .25) * Math.random(),
        d = Math.random() * Math.PI * 2;
    streamPositions[a] = Math.cos(d) * p, streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = Math.sin(d) * p, curRadiusArr[t] = p, spiralPhase[t] = d, streamState[t] = STATE_ON_DISK, startTimes[t] = e - Math.random() * (rOuter - .25) / .9, ascendStart[t] = 10 * Math.random(), streamRiseDuration[t] = 8 + 4 * Math.random();
    const h = .5 + 1.5 * Math.random(),
        u = Math.random() < .5 ? -1 : 1;
    extraRotArr[t] = 2 * h * Math.PI * u;
    const A = idxToTopIdx[o]; - 1 !== A && (topAlpha[A] = 1, staticGeo.attributes.alpha.needsUpdate = !0), activeImages.has(t) && releaseImageToPool(t), activeTexts.has(t) && releaseTextToPool(t), streamAlpha[t] = 1, streamGeo.attributes.alpha.needsUpdate = !0
}
const now0 = 0;
for (let t = 0; t < streamCount; t++) initializeStreamParticleState(t, 0);
streamGeo.attributes.position.needsUpdate = !0, streamGeo.attributes.alpha.needsUpdate = !0;
const clock = new THREE.Clock;
let initialColorApplied = false;

function mainAnimationLoop() {
    requestAnimationFrame(mainAnimationLoop);
    let t = clock.getDelta();
    const e = clock.getElapsedTime();
    if (t > 0.1) {
        t = 0.1;
    }

    // === HIá»†U á»¨NG GHÃ‰P Háº T THÃ€NH TRÃI TIM ===
    // Báº¯t Ä‘áº§u animation khi trang web load
    if (heartAssemblyStart === null) {
        heartAssemblyStart = e;
    }

    const assemblyProgress = Math.min((e - heartAssemblyStart) / HEART_ASSEMBLY_DURATION, 1.0);

    // Easing function má»m máº¡i hÆ¡n - easeOutExpo (giá»‘ng tia sÃ¡ng)
    function easeOutExpo(x) {
        return x === 1 ? 1 : 1 - Math.pow(2, -10 * x);
    }
    
    // Easing function vá»›i Ä‘Æ°á»ng cong mÆ°á»£t mÃ 
    function easeOutQuint(x) {
        return 1 - Math.pow(1 - x, 5);
    }
    
    if (assemblyProgress < 1.0) {
        // Animate top particles vá»›i delay vÃ  easing má»m máº¡i
        const topPosArray = staticGeo.attributes.position.array;
        for (let i = 0; i < topPosArray.length; i += 3) {
            const particleIndex = i / 3;
            const delay = topDelayArray[particleIndex];
            const adjustedTime = Math.max(0, (e - heartAssemblyStart - delay) / (HEART_ASSEMBLY_DURATION - delay * 0.5));
            const particleProgress = Math.min(adjustedTime, 1.0);
            
            // Sá»­ dá»¥ng easeOutExpo Ä‘á»ƒ táº¡o hiá»‡u á»©ng má»m máº¡i nhÆ° tia sÃ¡ng
            const easedProgress = easeOutExpo(particleProgress);
            
            // ThÃªm má»™t chÃºt Ä‘Æ°á»ng cong trong quÃ¡ trÃ¬nh di chuyá»ƒn
            const midPoint = easedProgress * 0.5;
            const curveOffset = Math.sin(easedProgress * Math.PI) * 2; // Táº¡o Ä‘Æ°á»ng cong nháº¹
            
            const startX = topStartPositions[i];
            const startY = topStartPositions[i + 1];
            const startZ = topStartPositions[i + 2];
            const targetX = topTargetPositions[i];
            const targetY = topTargetPositions[i + 1];
            const targetZ = topTargetPositions[i + 2];
            
            // TÃ­nh toÃ¡n vector hÆ°á»›ng
            const dirX = targetX - startX;
            const dirY = targetY - startY;
            const dirZ = targetZ - startZ;
            
            // ThÃªm Ä‘Æ°á»ng cong vuÃ´ng gÃ³c vá»›i hÆ°á»›ng di chuyá»ƒn
            const crossX = dirY * 0.1 - dirZ * 0.05;
            const crossY = dirZ * 0.1 - dirX * 0.05;
            const crossZ = dirX * 0.05 - dirY * 0.1;
            
            topPosArray[i] = THREE.MathUtils.lerp(startX, targetX, easedProgress) + crossX * curveOffset;
            topPosArray[i + 1] = THREE.MathUtils.lerp(startY, targetY, easedProgress) + crossY * curveOffset;
            topPosArray[i + 2] = THREE.MathUtils.lerp(startZ, targetZ, easedProgress) + crossZ * curveOffset;
        }
        staticGeo.attributes.position.needsUpdate = true;

        // Animate bottom particles vá»›i delay vÃ  easing má»m máº¡i
        const bottomPosArray = bottomGeo.attributes.position.array;
        for (let i = 0; i < bottomPosArray.length; i += 3) {
            const particleIndex = i / 3;
            const delay = bottomDelayArray[particleIndex];
            const adjustedTime = Math.max(0, (e - heartAssemblyStart - delay) / (HEART_ASSEMBLY_DURATION - delay * 0.5));
            const particleProgress = Math.min(adjustedTime, 1.0);
            const easedProgress = easeOutExpo(particleProgress);
            
            const curveOffset = Math.sin(easedProgress * Math.PI) * 2;
            const startX = bottomStartPositions[i];
            const startY = bottomStartPositions[i + 1];
            const startZ = bottomStartPositions[i + 2];
            const targetX = bottomTargetPositions[i];
            const targetY = bottomTargetPositions[i + 1];
            const targetZ = bottomTargetPositions[i + 2];
            
            const dirX = targetX - startX;
            const dirY = targetY - startY;
            const dirZ = targetZ - startZ;
            
            const crossX = dirY * 0.1 - dirZ * 0.05;
            const crossY = dirZ * 0.1 - dirX * 0.05;
            const crossZ = dirX * 0.05 - dirY * 0.1;
            
            bottomPosArray[i] = THREE.MathUtils.lerp(startX, targetX, easedProgress) + crossX * curveOffset;
            bottomPosArray[i + 1] = THREE.MathUtils.lerp(startY, targetY, easedProgress) + crossY * curveOffset;
            bottomPosArray[i + 2] = THREE.MathUtils.lerp(startZ, targetZ, easedProgress) + crossZ * curveOffset;
        }
        bottomGeo.attributes.position.needsUpdate = true;

        // Animate staticTopHeart particles vá»›i delay
        if (staticTopHeart && staticTopHeart.userData.startPositions && staticTopHeart.userData.targetPositions && staticTopHeart.userData.delayArray) {
            const staticTopPosArray = staticTopHeart.geometry.attributes.position.array;
            const startPos = staticTopHeart.userData.startPositions;
            const targetPos = staticTopHeart.userData.targetPositions;
            const delays = staticTopHeart.userData.delayArray;
            
            for (let i = 0; i < staticTopPosArray.length; i += 3) {
                const particleIndex = i / 3;
                const delay = delays[particleIndex];
                const adjustedTime = Math.max(0, (e - heartAssemblyStart - delay) / (HEART_ASSEMBLY_DURATION - delay * 0.5));
                const particleProgress = Math.min(adjustedTime, 1.0);
                const easedProgress = easeOutExpo(particleProgress);
                
                staticTopPosArray[i] = THREE.MathUtils.lerp(startPos[i], targetPos[i], easedProgress);
                staticTopPosArray[i + 1] = THREE.MathUtils.lerp(startPos[i + 1], targetPos[i + 1], easedProgress);
                staticTopPosArray[i + 2] = THREE.MathUtils.lerp(startPos[i + 2], targetPos[i + 2], easedProgress);
            }
            staticTopHeart.geometry.attributes.position.needsUpdate = true;
        }

        // Animate staticBottomHeart particles vá»›i delay
        if (staticBottomHeart && staticBottomHeart.userData.startPositions && staticBottomHeart.userData.targetPositions && staticBottomHeart.userData.delayArray) {
            const staticBottomPosArray = staticBottomHeart.geometry.attributes.position.array;
            const startPos = staticBottomHeart.userData.startPositions;
            const targetPos = staticBottomHeart.userData.targetPositions;
            const delays = staticBottomHeart.userData.delayArray;
            
            for (let i = 0; i < staticBottomPosArray.length; i += 3) {
                const particleIndex = i / 3;
                const delay = delays[particleIndex];
                const adjustedTime = Math.max(0, (e - heartAssemblyStart - delay) / (HEART_ASSEMBLY_DURATION - delay * 0.5));
                const particleProgress = Math.min(adjustedTime, 1.0);
                const easedProgress = easeOutExpo(particleProgress);
                
                staticBottomPosArray[i] = THREE.MathUtils.lerp(startPos[i], targetPos[i], easedProgress);
                staticBottomPosArray[i + 1] = THREE.MathUtils.lerp(startPos[i + 1], targetPos[i + 1], easedProgress);
                staticBottomPosArray[i + 2] = THREE.MathUtils.lerp(startPos[i + 2], targetPos[i + 2], easedProgress);
            }
            staticBottomHeart.geometry.attributes.position.needsUpdate = true;
        }
    } else {
        // assemblyProgress >= 1.0: Äáº£m báº£o cÃ¡c háº¡t luÃ´n á»Ÿ vá»‹ trÃ­ Ä‘Ã­ch (fix lá»—i khi tab background / thiáº¿t bá»‹ cháº­m nháº£y qua animation)
        const topPosArray = staticGeo.attributes.position.array;
        topPosArray.set(topTargetPositions);
        staticGeo.attributes.position.needsUpdate = true;
        const bottomPosArray = bottomGeo.attributes.position.array;
        bottomPosArray.set(bottomTargetPositions);
        bottomGeo.attributes.position.needsUpdate = true;
        if (staticTopHeart && staticTopHeart.userData.targetPositions) {
            staticTopHeart.geometry.attributes.position.array.set(staticTopHeart.userData.targetPositions);
            staticTopHeart.geometry.attributes.position.needsUpdate = true;
        }
        if (staticBottomHeart && staticBottomHeart.userData.targetPositions) {
            staticBottomHeart.geometry.attributes.position.array.set(staticBottomHeart.userData.targetPositions);
            staticBottomHeart.geometry.attributes.position.needsUpdate = true;
        }
    }
    // === Káº¾T THÃšC HIá»†U á»¨NG GHÃ‰P Háº T ===

    // Nhá»‹p sÃ¡ng tá»± Ä‘á»™ng cho cÃ¡c háº¡t stream (vÃ²ng xoÃ¡y quanh tim)
    // Dao Ä‘á»™ng opacity trong khoáº£ng [0.4, 1] theo thá»i gian Ä‘á»ƒ giá»‘ng hiá»‡u á»©ng phÃ¡t sÃ¡ng/pulse
    const streamPulse = 0.3 * Math.sin(e * 2.2) + 0.7;
    matStream.opacity = streamPulse;
    for (let e = 0; e < PLANE_COUNT; e++) {
        const a = 3 * e;
        let o = planePositions[a],
            s = planePositions[a + 2],
            r = Math.hypot(o, s);
        if (r > .25) {
            r = Math.max(.25, r - .9 * t);
            const e = Math.atan2(s, o);
            planePositions[a] = Math.cos(e) * r, planePositions[a + 2] = Math.sin(e) * r
        }
    }
    if (planeGeo.attributes.position.needsUpdate = !0, planeLayer.visible && (planeLayer.visible = !0)) {
        // Tá»‘c Ä‘á»™ quay cÃ³ boost ngáº¯n khi báº¯n áº£nh ra
        const rotationBoost = e < spinBoostUntil ? 5 : 1;
        planeRotationAngle += BASE_OMEGA * rotationBoost * t;
        planeLayer.rotation.y = planeRotationAngle;
        if (imageWallGroup) imageWallGroup.rotation.y = planeRotationAngle;
        if (void 0 !== ribbon) ribbon.rotation.y = planeRotationAngle + RING_FLIP_Y;
    }
    if (void 0 !== ribbon && ribbon.children.length) {
        const e = RING_START_RADIUS - .25;
        ribbon.children.forEach((a, o) => {
            a.userData.radius -= .9 * t, a.userData.radius - 1.75 < .25 && (a.userData.radius += e + 2);
            const s = a.userData.radius - 1.75;
            if (s < 1.25) {
                const t = THREE.MathUtils.clamp((s - .25) / 1, 0, 1);
                a.material.opacity = t
            }
            s < .25 && (a.userData.radius += e + 2, a.material.opacity = 0), a.material.opacity < 1 && (a.material.opacity = Math.min(1, a.material.opacity + 2 * t));
            const r = a.userData.radius / RING_START_RADIUS;
            a.scale.set(r, 3.5, r), a.material.color.set(16777215), a.rotation.y = a.userData.phase
        })
    }
    camera.updateMatrixWorld();
    const a = camera.matrixWorldInverse;
    // Bá»¥i vÅ© trá»¥ Ä‘Æ°á»£c khá»Ÿi táº¡o trá»…, nÃªn cáº§n kiá»ƒm tra tá»“n táº¡i trÆ°á»›c khi quay
    if (cosmicDust) {
        cosmicDust.rotation.y += 0.00015;
    }
    
    // === FADE IN CÃC TRÃI TIM MINI SAU KHI TRÃI TIM Lá»šN HOÃ€N THÃ€NH ===
    if (assemblyProgress >= 1.0) {
        // TrÃ¡i tim lá»›n Ä‘Ã£ hoÃ n thÃ nh, báº¯t Ä‘áº§u fade in cÃ¡c trÃ¡i tim mini
        if (miniHeartsFadeStart === null) {
            miniHeartsFadeStart = e;
        }
        
        const fadeElapsed = e - miniHeartsFadeStart;
        const fadeProgress = Math.min(fadeElapsed / MINI_HEARTS_FADE_DURATION, 1.0);
        
        // Fade in tá»«ng trÃ¡i tim vá»›i delay nhá»
        if (miniHearts && miniHearts.length > 0) {
            miniHearts.forEach((miniHeart, index) => {
                if (miniHeart && miniHeart.material) {
                    // Fade in vÃ  bay ra ngoÃ i tá»« trung tÃ¢m
                    const fadeProgress = Math.min(fadeElapsed / MINI_HEARTS_FADE_DURATION, 1.0);
                    const flyProgress = Math.min(fadeElapsed / MINI_HEARTS_FLY_OUT_DURATION, 1.0);
                    
                    // Easing má»m máº¡i cho fade in
                    const easedFadeProgress = 1 - Math.pow(1 - fadeProgress, 3);
                    miniHeart.material.opacity = easedFadeProgress;
                    
                    // === BAY Tá»ª TRUNG TÃ‚M RA NGOÃ€I ===
                    if (miniHeart.userData.startPosition && miniHeart.userData.targetPosition) {
                        const startPos = miniHeart.userData.startPosition;
                        const targetPos = miniHeart.userData.targetPosition;
                        
                        // Easing cho bay ra (easeOutExpo Ä‘á»ƒ mÆ°á»£t hÆ¡n)
                        const easedFlyProgress = flyProgress === 1 ? 1 : 1 - Math.pow(2, -10 * flyProgress);
                        
                        // ThÃªm delay nhá» cho má»—i trÃ¡i tim Ä‘á»ƒ táº¡o hiá»‡u á»©ng sÃ³ng nhÆ° Ä‘Ã n ong
                        const delay = index * 0.05; // Delay 0.05 giÃ¢y giá»¯a má»—i trÃ¡i tim
                        const adjustedFlyProgress = Math.max(0, Math.min(1, (fadeElapsed - delay) / MINI_HEARTS_FLY_OUT_DURATION));
                        const finalFlyProgress = adjustedFlyProgress === 1 ? 1 : 1 - Math.pow(2, -10 * adjustedFlyProgress);
                        
                        // Interpolate tá»« vá»‹ trÃ­ trung tÃ¢m Ä‘áº¿n vá»‹ trÃ­ Ä‘Ã­ch
                        const currentX = THREE.MathUtils.lerp(startPos.x, targetPos.x, finalFlyProgress);
                        const currentY = THREE.MathUtils.lerp(startPos.y, targetPos.y, finalFlyProgress);
                        const currentZ = THREE.MathUtils.lerp(startPos.z, targetPos.z, finalFlyProgress);
                        
                        miniHeart.position.set(currentX, currentY, currentZ);
                        
                        // ÄÃ¡nh dáº¥u Ä‘Ã£ Ä‘áº¿n vá»‹ trÃ­ Ä‘Ã­ch
                        if (finalFlyProgress >= 1.0) {
                            miniHeart.userData.hasReachedTarget = true;
                        }
                    }
                    // === Káº¾T THÃšC BAY RA NGOÃ€I ===
                    
                    // === NHá»ŠP Äáº¬P CHO TRÃI TIM MINI ===
                    let finalScale = 1;
                    
                    // Nhá»‹p Ä‘áº­p liÃªn tá»¥c nháº¹ (giá»‘ng heartbeatEnabled cá»§a trÃ¡i tim lá»›n)
                    if (heartbeatEnabled) {
                        const heartbeatScale = 1 + HEARTBEAT_AMPLITUDE * Math.sin(HEARTBEAT_FREQ_HZ * e * Math.PI * 2);
                        finalScale = heartbeatScale;
                    }
                    
                    // Nhá»‹p Ä‘áº­p máº¡nh khi click (giá»‘ng isPulsing cá»§a trÃ¡i tim lá»›n)
                    if (isPulsing) {
                        const pulseProgress = Math.min((e - pulseStartTime) / PULSE_DURATION, 1.0);
                        const pulseSine = Math.sin(pulseProgress * Math.PI);
                        const pulseScale = 1 + PULSE_AMPLITUDE * pulseSine;
                        finalScale = pulseScale;
                    }
                    
                    miniHeart.scale.set(finalScale, finalScale, finalScale);
                    // === Káº¾T THÃšC NHá»ŠP Äáº¬P ===
                    
                    // === BAY LÆ¯á»¢N LÆ  Lá»¬NG (chá»‰ khi Ä‘Ã£ Ä‘áº¿n vá»‹ trÃ­ Ä‘Ã­ch) ===
                    if (miniHeart.userData.hasReachedTarget && miniHeart.userData.targetPosition) {
                        const targetPos = miniHeart.userData.targetPosition;
                        
                        // Bay lÃªn xuá»‘ng nháº¹ (floating)
                        const floatY = Math.sin(e * miniHeart.userData.floatSpeed + miniHeart.userData.floatPhase) * miniHeart.userData.floatAmplitude;
                        
                        // Quay quanh vá»‹ trÃ­ Ä‘Ã­ch theo Ä‘Æ°á»ng trÃ²n nhá» (orbit)
                        const orbitAngle = e * miniHeart.userData.orbitSpeed + miniHeart.userData.orbitPhase;
                        const orbitX = Math.cos(orbitAngle) * miniHeart.userData.orbitRadius;
                        const orbitZ = Math.sin(orbitAngle) * miniHeart.userData.orbitRadius;
                        
                        // Cáº­p nháº­t vá»‹ trÃ­ (quanh vá»‹ trÃ­ Ä‘Ã­ch)
                        miniHeart.position.set(
                            targetPos.x + orbitX,
                            targetPos.y + floatY,
                            targetPos.z + orbitZ
                        );
                        
                        // Quay nháº¹ Ä‘á»ƒ tá»± nhiÃªn hÆ¡n
                        miniHeart.rotation.y += t * 0.2;
                    }
                    // === Káº¾T THÃšC BAY LÆ¯á»¢N ===
                }
            });
        }

        // (ÄÃ£ táº¯t: áº£nh bay tá»« trung tÃ¢m ra ngoÃ i â€” chá»‰ giá»¯ vÃ²ng quay áº£nh imageWallGroup)

        // Cáº­p nháº­t vá»‹ trÃ­ + opacity (staggered fade-in) cÃ¡c cÃ¢u chÃºc xoay quanh
        if (orbitingWishGroup && orbitingWishGroup.children.length > 0) {
            if (orbitingWishAppearStart === null) orbitingWishAppearStart = e;
            const elapsed = e - orbitingWishAppearStart;
            orbitingWishGroup.children.forEach(sprite => {
                if (!sprite.userData.orbitSpeed) return;
                sprite.userData.orbitAngle += sprite.userData.orbitSpeed * t;
                const r = sprite.userData.orbitRadius;
                const angle = sprite.userData.orbitAngle;
                const floatY = Math.sin(e * sprite.userData.floatSpeed + sprite.userData.floatPhase) * sprite.userData.floatAmplitude;
                sprite.position.set(Math.cos(angle) * r, sprite.userData.baseY + floatY, Math.sin(angle) * r);
                // Fade-in tá»« tá»«: sau appearDelay giÃ¢y thÃ¬ fade trong ORBIT_WISH_FADE_DURATION giÃ¢y
                const startAt = sprite.userData.appearDelay;
                if (elapsed <= startAt) {
                    sprite.material.opacity = 0;
                } else {
                    const fadeProgress = (elapsed - startAt) / ORBIT_WISH_FADE_DURATION;
                    sprite.material.opacity = Math.min(1, fadeProgress);
                }
            });
        }
    }
    // === Káº¾T THÃšC FADE IN TRÃI TIM MINI ===
    
    if (streamHeartStarted) {
        streamHeart.matrixWorld, new THREE.Vector3, new THREE.Vector3;
        const t = 1e3 * e;
        controlImageSpawningLogic(t), handleQueuedImageSpawns(), animateFloatingImageSprites(t), t - lastStatusLogTime > 3e3 && (printImageSystemReport(), lastStatusLogTime = t);
        for (let t = 0; t < streamCount; t++) {
            const a = 3 * t,
                o = startTimes[t],
                s = e - (o + t % 5 * 1.6),
                r = targetIdxArr[t];
            if (streamState[t] === STATE_ON_DISK) {
                const o = spiralPhase[t] + BASE_OMEGA * (e - startTimes[t]);
                streamPositions[a] = Math.cos(o) * curRadiusArr[t], streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = Math.sin(o) * curRadiusArr[t], activeImages.has(t) && releaseImageToPool(t), streamAlpha[t] = 1, s >= ascendStart[t] && (streamState[t] = STATE_ASCEND, startTimes[t] = e, initialRadius[t] = curRadiusArr[t]);
                continue
            }
            if (s < -1.5) {
                const s = spiralPhase[t] + BASE_OMEGA * (e - o);
                streamPositions[a] = initialRadius[t] * Math.cos(s), streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = initialRadius[t] * Math.sin(s), streamAlpha[t] = 0;
                continue
            }
            if (s < 0) {
                const r = (s + 1.5) / 1.5,
                    i = r * r * (3 - 2 * r);
                streamAlpha[t] = i, activeImages.has(t) && releaseImageToPool(t);
                const n = spiralPhase[t] + BASE_OMEGA * (e - o);
                streamPositions[a] = initialRadius[t] * Math.cos(n), streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = initialRadius[t] * Math.sin(n);
                continue
            }
            const i = streamRiseDuration[t];
            if (s >= i) {
                const r = (s - i) / 1.5;
                if (r < 1) {
                    const s = r * r * (3 - 2 * r);
                    if (streamAlpha[t] = 1 - s, activeImages.has(t)) {
                        const e = activeImages.get(t);
                        imagePool[e].material.opacity *= 1 - s
                    }
                    const i = spiralPhase[t] + BASE_OMEGA * (e - o);
                    streamPositions[a] = initialRadius[t] * Math.cos(i), streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = initialRadius[t] * Math.sin(i);
                    continue
                }
                streamAlpha[t] = 1, activeImages.has(t) && releaseImageToPool(t), initializeStreamParticleState(t, e), firstResetCompleted || (firstResetCompleted = !0);
                continue
            }
            streamAlpha[t] = 1;
            const n = s / i;
            if (n < .01) {
                let s, r, i;
                const l = spiralPhase[t] + BASE_OMEGA * (e - o);
                {
                    const e = initialRadius[t];
                    s = Math.cos(l) * e, i = Math.sin(l) * e;
                    const a = Math.min(1, n / .01);
                    r = THREE.MathUtils.lerp(planeYCenter, apexY, a)
                }
                streamPositions[a] = s, streamPositions[a + 1] = r, streamPositions[a + 2] = i
            } else {
                const s = (n - .01) / .99,
                    i = 1 - Math.pow(1 - s, 3),
                    l = spiralPhase[t] + BASE_OMEGA * (e - o),
                    m = initialRadius[t],
                    c = Math.cos(l) * m,
                    p = Math.sin(l) * m,
                    d = apexY,
                    h = 3 * r,
                    u = positions[h],
                    A = positions[h + 1] - 4 + 2,
                    E = positions[h + 2];
                let T = THREE.MathUtils.lerp(c, u, i),
                    f = THREE.MathUtils.lerp(d, A, i),
                    S = THREE.MathUtils.lerp(p, E, i);
                const I = 1 + .1 * (1 - i);
                T *= I, S *= I;
                const g = (1 - i) * extraRotArr[t],
                    b = Math.cos(g),
                    M = Math.sin(g),
                    P = T * b - S * M,
                    R = T * M + S * b;
                streamPositions[a] = P, streamPositions[a + 1] = f, streamPositions[a + 2] = R
            }
            if (n < .01) streamAlpha[t] = 1, activeImages.has(t) && releaseImageToPool(t);
            else {
                const e = (n - .01) / .99;
                let a = null;
                if (activeImages.has(t)) {
                    const e = activeImages.get(t);
                    a = imagePool[e]
                }
                if (a) {
                    streamAlpha[t] = 0, a.visible = !0;
                    const o = 1 - Math.pow(1 - e, 3),
                        s = 3 * r,
                        i = positions[s],
                        n = positions[s + 1] - 4 + 2,
                        l = positions[s + 2],
                        m = 1 + t % 5 * .2,
                        c = t % 2 == 0 ? 1 : -1,
                        p = spiralPhase[t] + o * m * Math.PI * 2 * c,
                        d = (1 - o) * (2 + 1 * Math.sin(t)),
                        h = THREE.MathUtils.lerp(0, i, o),
                        u = THREE.MathUtils.lerp(apexY, n, o),
                        A = THREE.MathUtils.lerp(0, l, o),
                        E = h + Math.cos(p) * d,
                        T = u,
                        f = A + Math.sin(p) * d;
                    if (a.position.set(E, T, f), o > .4) {
                        const e = (o - .4) / .6,
                            s = 1;
                        a.material.opacity = s * (1 - e);
                        const r = 1 - .9 * e,
                            i = a.userData.aspectScale || {
                                x: IMAGE_CONFIG.scale,
                                y: IMAGE_CONFIG.scale
                            };
                        a.scale.set(i.x * r, i.y * r, 1), e > .9 && (a.visible = !1, releaseImageToPool(t))
                    } else {
                        a.material.opacity = 1;
                        const t = a.userData.aspectScale || {
                            x: IMAGE_CONFIG.scale,
                            y: IMAGE_CONFIG.scale
                        };
                        a.scale.set(t.x, t.y, 1)
                    }
                } else streamAlpha[t] = 1
            }
            if (streamGeo.attributes.size.needsUpdate = !0, n > .95) {
                const t = topIndices.indexOf(r);
                if (topPointVisibility[t] && hiddenTopCount < MAX_TOP_HIDE) {
                    topPointVisibility[t] = !1;
                    const e = idxToTopIdx[r]; - 1 !== e && (topAlpha[e] = 0, staticGeo.attributes.alpha.needsUpdate = !0), hiddenTopCount++
                }
            }
        }
    } else {
        for (let t = 0; t < streamCount; t++) {
            if (streamHeartActiveRatio < 1 && t / streamCount > .1) {
                const a = 3 * t,
                    o = spiralPhase[t] + BASE_OMEGA * e;
                streamPositions[a] = Math.cos(o) * curRadiusArr[t], streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = Math.sin(o) * curRadiusArr[t], streamAlpha[t] = 0;
                continue
            }
            if (!firstResetCompleted && t / streamCount > 1e-4) {
                const a = 3 * t,
                    o = spiralPhase[t] + BASE_OMEGA * e;
                streamPositions[a] = Math.cos(o) * curRadiusArr[t], streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = Math.sin(o) * curRadiusArr[t], streamAlpha[t] = 0;
                continue
            }
            const a = 3 * t,
                o = spiralPhase[t] + BASE_OMEGA * e;
            streamPositions[a] = Math.cos(o) * curRadiusArr[t], streamPositions[a + 1] = planeYCenter, streamPositions[a + 2] = Math.sin(o) * curRadiusArr[t], streamAlpha[t] = 0
        }
        streamGeo.attributes.position.needsUpdate = !0, streamGeo.attributes.alpha.needsUpdate = !0
    }
    streamGeo.attributes.position.needsUpdate = !0, streamGeo.attributes.alpha.needsUpdate = !0;
    for (let t = 0; t < vortexCount; t++) {
        const a = 3 * t,
            o = 1 * Math.PI / 10,
            s = vortexRadius[t],
            r = e * o,
            i = .3 * Math.sin(r + vortexPhase[t]),
            n = .2 * Math.cos(.7 * r + vortexPhase[t]),
            l = r + vortexPhase[t] + i,
            m = s * (1 + n);
        vortexPositions[a] = Math.cos(l) * m, vortexPositions[a + 1] = planeYCenter + .5 * Math.sin(r + vortexPhase[t]), vortexPositions[a + 2] = Math.sin(l) * m
    }
    vortexGeo.attributes.position.needsUpdate = !0;
    const o = bottomGeo.attributes.position.array;
    for (let t = 0; t < bottomCount; t++) {
        if (e < bottomDelayArr[t]) continue;
        const s = bottomPhaseArr[t],
            r = bottomRadiusArr[t],
            i = Math.cos(s) * r;
        if (Math.abs(s) < .25 * Math.PI) {
            const e = Math.min(1, Math.abs(i) / (.25 * heartWidth)),
                a = 1.5 * Math.pow(1 - e, 3) + 1,
                s = i >= 0 ? 1 : -1;
            o[3 * t] = i + s * (Math.abs(i) * (a - 1))
        } else o[3 * t] = i;
        o[3 * t + 2] = Math.sin(s) * r;
        const n = o[3 * t],
            l = o[3 * t + 1],
            m = o[3 * t + 2],
            c = new THREE.Vector3(n, l, m).applyMatrix4(bottomHeart.matrixWorld);
        (new THREE.Vector3).copy(c).applyMatrix4(a), bottomAlphaArr[t] = bottomAlphaBase[t]
    }
    bottomGeo.attributes.position.needsUpdate = !0, bottomGeo.attributes.alpha.needsUpdate = !0;
    const s = controls.getAzimuthalAngle();
    if (staticHeart && (staticHeart.rotation.y = s), bottomHeart && (bottomHeart.rotation.y = s), staticBottomHeart && (staticBottomHeart.rotation.y = s), staticTopHeart && (staticTopHeart.rotation.y = s), heartbeatEnabled) {
        const t = 1 + .05 * Math.sin(.5 * e * Math.PI * 2);
        staticHeart && staticHeart.scale.set(t, t, t), bottomHeart && bottomHeart.scale.set(t, t, t), staticBottomHeart && staticBottomHeart.scale.set(t, t, t), staticTopHeart && staticTopHeart.scale.set(t, t, t)
    }
    if (controls.update(), renderer.clear(), composerHeart.render(), renderer.clearDepth(), renderer.autoClear = !1, composerMain.render(), renderer.autoClear = !0, hiddenTopCount < MAX_TOP_HIDE) {
        for (let t = 0; t < 5 && hiddenTopCount < MAX_TOP_HIDE; t++) {
            const t = Math.floor(Math.random() * topIndices.length),
                e = topIndices[t];
            if (topPointVisibility[t]) {
                topPointVisibility[t] = !1;
                const a = idxToTopIdx[e]; - 1 !== a && (topAlpha[a] = 0, hiddenTopCount++)
            }
        }
        staticGeo.attributes.position.needsUpdate = !0, staticGeo.attributes.alpha.needsUpdate = !0
    }
    // -- Báº®T Äáº¦U: Cáº¬P NHáº¬T HIá»†U á»¨NG BÃ™NG Ná»” (CÃ“ Lá»°C HÃšT) --
    for (let i = explosionEffects.length - 1; i >= 0; i--) {
        const group = explosionEffects[i];
        group.userData.life -= t;

        if (group.userData.life <= 0) {
            // --- KÃCH HOáº T NHá»ŠP Äáº¬P Táº I ÄÃ‚Y ---
            // Chá»‰ báº¯t Ä‘áº§u má»™t nhá»‹p Ä‘áº­p má»›i náº¿u khÃ´ng cÃ³ nhá»‹p Ä‘áº­p nÃ o Ä‘ang diá»…n ra
            if (!isPulsing) {
                isPulsing = true;
                pulseStartTime = e; // 'e' lÃ  thá»i gian hiá»‡n táº¡i cá»§a clock
                triggerCosmicRipple(); // <<< THÃŠM DÃ’NG NÃ€Y Äá»‚ Táº O VÃ’NG HÃ€O QUANG
            }
            // --- Káº¾T THÃšC KÃCH HOáº T ---

            scene.remove(group);
            explosionEffects.splice(i, 1);
        } else {
            const points = group.children[0];
            const positions = points.geometry.attributes.position.array;
            const velocities = group.userData.velocities;

            // Háº±ng sá»‘ Ä‘iá»u chá»‰nh lá»±c hÃºt, báº¡n cÃ³ thá»ƒ thay Ä‘á»•i
            const attractionStrength = 0.04;

            for (let j = 0; j < velocities.length; j++) {
                const idx = j * 3;

                // Láº¥y vá»‹ trÃ­ vÃ  váº­n tá»‘c hiá»‡n táº¡i cá»§a háº¡t
                const currentPosition = new THREE.Vector3(positions[idx], positions[idx + 1], positions[idx + 2]);
                const currentVelocity = velocities[j];

                // --- LOGIC HÃšT Vá»€ TRÃI TIM ---
                // TÃ­nh toÃ¡n vector hÆ°á»›ng tá»« háº¡t vá» tÃ¢m trÃ¡i tim
                const toHeartVector = HEART_CENTER_TARGET.clone().sub(currentPosition);

                // Dáº§n dáº§n thay Ä‘á»•i váº­n tá»‘c cá»§a háº¡t Ä‘á»ƒ hÆ°á»›ng vá» phÃ­a trÃ¡i tim
                // lerp() giÃºp táº¡o ra Ä‘Æ°á»ng bay cong vÃ  mÆ°á»£t mÃ 
                currentVelocity.lerp(toHeartVector, attractionStrength);

                // Cáº­p nháº­t vá»‹ trÃ­ háº¡t dá»±a trÃªn váº­n tá»‘c Ä‘Ã£ Ä‘Æ°á»£c Ä‘iá»u chá»‰nh
                positions[idx] += currentVelocity.x * t;
                positions[idx + 1] += currentVelocity.y * t;
                positions[idx + 2] += currentVelocity.z * t;
            }
            points.geometry.attributes.position.needsUpdate = true;

            // LÃ m má» dáº§n khi sáº¯p káº¿t thÃºc
            if (group.userData.life < 1.0) {
                points.material.opacity = group.userData.life / 1.0;
            }
        }
    }
    // -- Káº¾T THÃšC: Cáº¬P NHáº¬T HIá»†U á»¨NG BÃ™NG Ná»” --

    // -- Báº®T Äáº¦U: Cáº¬P NHáº¬T HIá»†U á»¨NG HÃ€O QUANG (Tá»I Æ¯U) --
    const RIPPLE_LIFESPAN = 1.8; // KÃ©o dÃ i thá»i gian Ä‘á»ƒ lan tá»a rá»™ng hÆ¡n

    // Cáº­p nháº­t SÃ³ng NÄƒng LÆ°á»£ng
    effectPool.waves.forEach(wave => {
        if (!wave.userData.active) return;
        const progress = (e - wave.userData.creationTime) / RIPPLE_LIFESPAN;
        if (progress >= 1) {
            wave.userData.active = false;
            wave.visible = false;
        } else {
            // =============================================================
            // FIX: LuÃ´n hÆ°á»›ng máº·t pháº³ng vá» phÃ­a camera (Billboarding)
            wave.lookAt(camera.position);
            // =============================================================

            // Lan tá»a rá»™ng hÆ¡n, nháº¡t hÆ¡n
            wave.scale.set(1 + progress * 6, 1 + progress * 6, 1);
            wave.material.opacity = 0.6 * (1 - progress);
        }
    });

    // Cáº­p nháº­t Bá»¥i Sao (Pháº§n nÃ y khÃ´ng cáº§n thay Ä‘á»•i)
    effectPool.sparkles.forEach(sparkles => {
        if (!sparkles.userData.active) return;
        const progress = (e - sparkles.userData.creationTime) / RIPPLE_LIFESPAN;
        if (progress >= 1) {
            sparkles.userData.active = false;
            sparkles.visible = false;
        } else {
            const positions = sparkles.geometry.attributes.position.array;
            const velocities = sparkles.userData.velocities;
            for (let i = 0; i < 100; i++) {
                const idx = i * 3;
                positions[idx] += velocities[idx] * t;
                positions[idx + 1] += velocities[idx + 1] * t;
            }
            sparkles.geometry.attributes.position.needsUpdate = true;
            sparkles.material.opacity = 1 - Math.pow(progress, 2);
        }
    });


    // -- Táº®T HOÃ€N TOÃ€N LOGIC SPAWN Tá»ª Tá»ªNG Tá»ª - CHá»ˆ DÃ™NG CÃ‚U CHÃšC LÆ  Lá»¬NG --
    // KhÃ´ng spawn tá»« ná»¯a, chá»‰ dÃ¹ng orbiting wishes
    // KhÃ´ng cáº§n cáº­p nháº­t activeTexts vÃ¬ khÃ´ng cÃ²n spawn tá»«

    // -- Báº®T Äáº¦U: HIá»†U á»¨NG TIM Äáº¬P & PHáº¢N á»¨NG MÃ€U Sáº®C (LOGIC Sá»¬A Lá»–I) --
    const heartMeshes = [staticHeart, bottomHeart, staticBottomHeart, staticTopHeart];
    let finalColor = new THREE.Color();

    // LuÃ´n dÃ¹ng mÃ u Ä‘á» máº·c Ä‘á»‹nh, khÃ´ng Ä‘á»•i mÃ u Ä‘á»™ng
    finalColor.copy(heartInitialColor);

    if (isPulsing) {
        const pulseProgress = Math.min((e - pulseStartTime) / PULSE_DURATION, 1.0);
        const pulseSine = Math.sin(pulseProgress * Math.PI);
        const scale = 1 + PULSE_AMPLITUDE * pulseSine;
        heartMeshes.forEach(mesh => { if (mesh) mesh.scale.set(scale, scale, scale); });

        const flashColor = new THREE.Color(0xffffff);
        finalColor.lerp(flashColor, pulseSine * 0.8);

        if (pulseProgress >= 1.0) {
            isPulsing = false;
            heartMeshes.forEach(mesh => { if (mesh) mesh.scale.set(1, 1, 1); });
        }
    }

    // Sá»¬A Lá»–I: Cháº¡y cáº­p nháº­t mÃ u náº¿u (mÃ u lÃ  Ä‘á»™ng) HOáº¶C (Ä‘ang pulsing) HOáº¶C (chÆ°a Ã¡p dá»¥ng mÃ u ban Ä‘áº§u)
    // LuÃ´n Ã¡p dá»¥ng mÃ u Ä‘á»
    if (isPulsing || !initialColorApplied) {
        const n = finalColor.r, l = finalColor.g, m = finalColor.b;

        function updateParticleColorArray(attributeArray) {
            if (!attributeArray) return;
            for (let i = 0; i < attributeArray.length; i += 3) {
                attributeArray[i] = n;
                attributeArray[i + 1] = l;
                attributeArray[i + 2] = m;
            }
        }

        updateParticleColorArray(planeGeo.attributes.color.array);
        updateParticleColorArray(staticGeo.attributes.color.array);
        updateParticleColorArray(bottomGeo.attributes.color.array);
        if (staticBottomHeart) updateParticleColorArray(staticBottomHeart.geometry.attributes.color.array);
        if (staticTopHeart) updateParticleColorArray(staticTopHeart.geometry.attributes.color.array);
        updateParticleColorArray(vortexGeo.attributes.color.array);
        updateParticleColorArray(streamGeo.attributes.color.array);

        planeGeo.attributes.color.needsUpdate = true;
        staticGeo.attributes.color.needsUpdate = true;
        bottomGeo.attributes.color.needsUpdate = true;
        if (staticBottomHeart) staticBottomHeart.geometry.attributes.color.needsUpdate = true;
        if (staticTopHeart) staticTopHeart.geometry.attributes.color.needsUpdate = true;
        vortexGeo.attributes.color.needsUpdate = true;
        streamGeo.attributes.color.needsUpdate = true;

        ribbon.children.forEach(t => {
            t.material.color.setRGB(n, l, m);
        });

        // ÄÃ¡nh dáº¥u lÃ  Ä‘Ã£ Ã¡p dá»¥ng mÃ u ban Ä‘áº§u xong, Ä‘á»ƒ tá»‘i Æ°u cho cÃ¡c frame sau
        initialColorApplied = true;
    }
    // -- Káº¾T THÃšC: HIá»†U á»¨NG TIM Äáº¬P & PHáº¢N á»¨NG MÃ€U Sáº®C --

    if (e >= nextShootTime) {
        for (let t = 0; t < SHOOT_MAX; t++)
            if (shootLife[t] <= 0) {
                const a = 3 * t;
                const SPAWN_RADIUS = 200; // BÃ¡n kÃ­nh cá»§a vÃ¹ng trá»i nÆ¡i sao bÄƒng sáº½ xuáº¥t hiá»‡n

                // 1. Táº¡o vá»‹ trÃ­ báº¯t Ä‘áº§u ngáº«u nhiÃªn trÃªn má»™t máº·t cáº§u lá»›n Ä‘á»ƒ Ä‘áº£m báº£o nÃ³ luÃ´n á»Ÿ phÃ­a sau
                const startPos = new THREE.Vector3(
                    (Math.random() - 0.5) * 2,
                    (Math.random() - 0.5) * 2,
                    (Math.random() - 0.5) * 2
                ).normalize().multiplyScalar(SPAWN_RADIUS);

                shootPositions[a] = startPos.x;
                shootPositions[a + 1] = startPos.y;
                shootPositions[a + 2] = startPos.z;

                // 2. Táº¡o má»™t vector váº­n tá»‘c tiáº¿p tuyáº¿n vá»›i máº·t cáº§u, giÃºp sao bÄƒng bay ngang qua báº§u trá»i má»™t cÃ¡ch tá»± nhiÃªn
                const randomVec = new THREE.Vector3(
                    (Math.random() - 0.5),
                    (Math.random() - 0.5),
                    (Math.random() - 0.5)
                ).normalize();
                const tangentVec = new THREE.Vector3().crossVectors(startPos, randomVec).normalize();

                const s = 40 + 30 * Math.random(); // TÄƒng tá»‘c Ä‘á»™ Ä‘á»ƒ phÃ¹ há»£p vá»›i khÃ´ng gian lá»›n hÆ¡n
                shootVel[a] = tangentVec.x * s;
                shootVel[a + 1] = tangentVec.y * s;
                shootVel[a + 2] = tangentVec.z * s;
                shootBirth[t] = e;

                // 3. TÃ­nh toÃ¡n thá»i gian sá»‘ng cá»§a sao bÄƒng dá»±a trÃªn quÃ£ng Ä‘Æ°á»ng nÃ³ bay
                shootLife[t] = (SHOOT_OUT_RADIUS - SPAWN_RADIUS) / s;
                shootAlpha[t] = .8 + .2 * Math.random();
                break; // Dá»«ng láº¡i sau khi táº¡o thÃ nh cÃ´ng má»™t sao bÄƒng
            }
        nextShootTime = e + 0.5 + Math.random(); // Äiá»u chá»‰nh thá»i gian xuáº¥t hiá»‡n sao bÄƒng tiáº¿p theo
    }
    for (let e = 0; e < SHOOT_MAX; e++)
        if (shootLife[e] > 0) {
            const a = 3 * e;
            shootPositions[a] += shootVel[a] * t, shootPositions[a + 1] += shootVel[a + 1] * t, shootPositions[a + 2] += shootVel[a + 2] * t;
            const o = Math.hypot(shootPositions[a], shootPositions[a + 1], shootPositions[a + 2]);
            if (shootBirth[e], shootLife[e], o > SHOOT_OUT_RADIUS) shootLife[e] = 0, shootAlpha[e] = 0;
            else {
                const t = .9,
                    a = o / SHOOT_OUT_RADIUS;
                shootAlpha[e] = a > t ? 1 - (a - t) / (1 - t) : 1
            }
            const s = e * (TAIL_SEGMENTS + 1),
                r = 3 * s;
            tailPositions[r] = shootPositions[a], tailPositions[r + 1] = shootPositions[a + 1], tailPositions[r + 2] = shootPositions[a + 2], tailAlphas[s] = shootAlpha[e];
            for (let t = 1; t <= TAIL_SEGMENTS; t++) {
                const o = e * (TAIL_SEGMENTS + 1) + t,
                    s = 3 * o;
                tailPositions[s] = shootPositions[a] - shootVel[a] * t * TAIL_SPACING, tailPositions[s + 1] = shootPositions[a + 1] - shootVel[a + 1] * t * TAIL_SPACING, tailPositions[s + 2] = shootPositions[a + 2] - shootVel[a + 2] * t * TAIL_SPACING;
                const r = 1 - t / TAIL_SEGMENTS;
                tailAlphas[o] = shootAlpha[e] * r
            }
        } if (tailGeo.attributes.position.needsUpdate = !0, tailGeo.attributes.alpha.needsUpdate = !0, heartbeatEnabled) {
            const t = 1 + .05 * Math.sin(.5 * e * Math.PI * 2);
            staticHeart && staticHeart.scale.set(t, t, t), bottomHeart && bottomHeart.scale.set(t, t, t), staticBottomHeart && staticBottomHeart.scale.set(t, t, t), staticTopHeart && staticTopHeart.scale.set(t, t, t)
        }
    if (null !== revealStart && (fadeObjects.forEach(t => {
        if (!t || t === ribbon) return;
        const a = t.userData.fadeStage ?? 0,
            o = THREE.MathUtils.clamp((e - revealStart - STAGE_DURATION * a) / STAGE_DURATION, 0, 1),
            s = o * o * (3 - 2 * o);
        t.traverse?.(child => {
            const material = child.material;
            if (!material) return;

            if (child.isSprite && child.userData.text && child.userData.active === false) {
                material.opacity = 0;
                return;
            }
            const baseOpacity = child.userData.baseOpacity ?? 1;
            material.opacity = baseOpacity * s
        }), a === STAGE.STREAM && s > .1 && (streamHeartStarted = !0, streamHeartActiveRatio = s)
    }), e - revealStart > STAGE_DURATION * (STAGE.HEART + 1) && (revealStart = null)), null !== cameraAnimationStart) {
        const t = e - cameraAnimationStart,
            a = THREE.MathUtils.clamp(t / CAMERA_ANIMATION_DURATION, 0, 1),
            o = a * a * (3 - 2 * a); // ÄÃ£ sá»­a lá»—i nhá» á»Ÿ Ä‘Ã¢y tá»« 'o' thÃ nh 'a'
        camera.position.x = THREE.MathUtils.lerp(CAMERA_START_POSITION.x, CAMERA_END_POSITION.x, o), camera.position.y = THREE.MathUtils.lerp(CAMERA_START_POSITION.y, CAMERA_END_POSITION.y, o), camera.position.z = THREE.MathUtils.lerp(CAMERA_START_POSITION.z, CAMERA_END_POSITION.z, o), camera.lookAt(0, 0, 0), a >= 1 && (cameraAnimationStart = null, camera.position.set(CAMERA_END_POSITION.x, CAMERA_END_POSITION.y, CAMERA_END_POSITION.z), camera.lookAt(0, 0, 0))
    }
}
// HÃ m kÃ­ch hoáº¡t hiá»‡u á»©ng tá»« "há»“ chá»©a"
function triggerCosmicRipple() {
    const pulseColor = new THREE.Color().setHSL((clock.getElapsedTime() * 0.05) % 1, 0.9, 0.7);
    // KÃ­ch hoáº¡t má»™t SÃ³ng NÄƒng LÆ°á»£ng
    const wave = effectPool.waves.find(w => !w.userData.active);
    if (wave) {
        wave.userData.active = true;
        wave.visible = true;
        wave.userData.creationTime = clock.getElapsedTime();
        wave.position.copy(HEART_CENTER_TARGET);
        wave.rotation.z = Math.PI;
        wave.scale.set(1, 1, 1);
        wave.material.color.copy(pulseColor);
    }

    // KÃ­ch hoáº¡t má»™t nhÃ³m Bá»¥i Sao
    const sparkles = effectPool.sparkles.find(s => !s.userData.active);
    if (sparkles) {
        sparkles.userData.active = true;
        sparkles.visible = true;
        sparkles.userData.creationTime = clock.getElapsedTime();
        sparkles.position.copy(HEART_CENTER_TARGET);
        sparkles.rotation.z = Math.PI;
        sparkles.material.color.copy(pulseColor);

        // Äiá»n dá»¯ liá»‡u vÃ o geometry Ä‘Ã£ cÃ³ sáºµn
        const positions = sparkles.geometry.attributes.position.array;
        for (let i = 0; i < 100; i++) {
            const angle = Math.random() * Math.PI * 2;
            const radius = 9;
            const speed = Math.random() * 20 + 20; // TÄƒng tá»‘c Ä‘á»™ lan tá»a
            const idx = i * 3;

            // Vá»‹ trÃ­ ban Ä‘áº§u
            positions[idx] = Math.cos(angle) * radius;
            positions[idx + 1] = Math.sin(angle) * radius;
            positions[idx + 2] = (Math.random() - 0.5) * 5;

            // LÆ°u váº­n tá»‘c vÃ o userData Ä‘á»ƒ dÃ¹ng trong animation
            if (!sparkles.userData.velocities) sparkles.userData.velocities = [];
            sparkles.userData.velocities[idx] = Math.cos(angle) * speed;
            sparkles.userData.velocities[idx + 1] = Math.sin(angle) * speed;
            sparkles.userData.velocities[idx + 2] = (Math.random() - 0.5) * 5;
        }
        sparkles.geometry.attributes.position.needsUpdate = true;
    }
}
setupEffectPools();
createOrbitingWishSprites();
window.addEventListener("resize", () => {
    camera.aspect = window.innerWidth / window.innerHeight, camera.updateProjectionMatrix(), renderer.setSize(window.innerWidth, window.innerHeight)
});
const refinedBottomPos = [],
    refinedBottomColors = [],
    refinedBottomSizes = [];
for (let t = 0; t < bottomPositions.length; t += 3) {
    const e = bottomPositions[t],
        a = bottomPositions[t + 1],
        o = bottomPositions[t + 2];
    (calculateMinimumDistanceToBorder(e, a) < BORDER_THRESHOLD || Math.random() < .9) && (refinedBottomPos.push(e, a, o), refinedBottomColors.push(heartInitialColor.r, heartInitialColor.g, heartInitialColor.b), refinedBottomSizes.push(bottomSizes[t / 3]))
}
bottomPositions = refinedBottomPos, bottomColors.length = 0, bottomColors.push(...refinedBottomColors), bottomSizes.length = 0, bottomSizes.push(...refinedBottomSizes);

const starLayers = [];
function createStarLayer({ count, radius, colors, minSize, maxSize, opacity = 1.2 }) {
    const positions = new Float32Array(count * 3);
    const colorsAttr = new Float32Array(count * 3);
    const sizes = new Float32Array(count);
    const alpha = new Float32Array(count);
    const phase = new Float32Array(count);
    const twinkleSpeed = new Float32Array(count);

    for (let i = 0; i < count; i++) {
        const i3 = i * 3;

        // Vá»‹ trÃ­ ngáº«u nhiÃªn trÃªn má»™t máº·t cáº§u áº£o Ä‘á»ƒ sao bao quanh toÃ n bá»™ cáº£nh
        const phi = Math.acos((2 * Math.random()) - 1);
        const theta = Math.random() * Math.PI * 2;

        positions[i3] = radius * Math.cos(theta) * Math.sin(phi);
        positions[i3 + 1] = radius * Math.sin(theta) * Math.sin(phi);
        positions[i3 + 2] = radius * Math.cos(phi);

        // Chá»n má»™t mÃ u ngáº«u nhiÃªn tá»« báº£ng mÃ u Ä‘Æ°á»£c cung cáº¥p. Äiá»u nÃ y táº¡o ra sá»± Ä‘a dáº¡ng.
        const color = colors[Math.floor(Math.random() * colors.length)];
        colorsAttr[i3] = color.r;
        colorsAttr[i3 + 1] = color.g;
        colorsAttr[i3 + 2] = color.b;

        // KÃ­ch thÆ°á»›c ngáº«u nhiÃªn trong má»™t khoáº£ng cho trÆ°á»›c.
        sizes[i] = Math.random() * (maxSize - minSize) + minSize;

        // LÆ°u trá»¯ cÃ¡c thuá»™c tÃ­nh cho viá»‡c nháº¥p nhÃ¡y: má»—i sao cÃ³ má»™t pha vÃ  tá»‘c Ä‘á»™ riÃªng.
        alpha[i] = 1;
        phase[i] = Math.random() * Math.PI * 2;
        twinkleSpeed[i] = 0.5 + Math.random() * 1.5;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geo.setAttribute('color', new THREE.BufferAttribute(colorsAttr, 3));
    geo.setAttribute('size', new THREE.BufferAttribute(sizes, 1));
    geo.setAttribute('alpha', new THREE.BufferAttribute(alpha, 1).setUsage(THREE.DynamicDrawUsage));

    // LÆ°u trá»¯ cÃ¡c giÃ¡ trá»‹ phase vÃ  speed vÃ o userData Ä‘á»ƒ dÃ¹ng trong vÃ²ng láº·p animation
    geo.userData.phase = phase;
    geo.userData.twinkleSpeed = twinkleSpeed;

    const mat = makeMat({
        map: circleTexture,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        alphaSupport: true,
        opacity: opacity,
        sizeAttenuation: false, // Ráº¥t quan trá»ng: Giá»¯ kÃ­ch thÆ°á»›c sao khÃ´ng Ä‘á»•i dÃ¹ camera xa hay gáº§n.
        vertexColors: true
    });

    // Äoáº¡n mÃ£ shader nÃ y Ä‘áº£m báº£o Ä‘á»™ má» (alpha) cá»§a má»—i sao cÃ³ thá»ƒ Ä‘Æ°á»£c Ä‘iá»u khiá»ƒn riÃªng láº».
    mat.onBeforeCompile = function (shader) {
        shader.vertexShader = shader.vertexShader.replace("uniform float size;", "attribute float size; attribute float alpha; varying float vAlpha;");
        shader.vertexShader = shader.vertexShader.replace("#include <project_vertex>", "#include <project_vertex>\n  vAlpha = alpha;");
        shader.fragmentShader = shader.fragmentShader.replace("void main() {", "varying float vAlpha;\nvoid main(){");
        shader.fragmentShader = shader.fragmentShader.replace("gl_FragColor = vec4( outgoingLight, diffuseColor.a );", "gl_FragColor = vec4( outgoingLight, diffuseColor.a * vAlpha );");
    };

    return new THREE.Points(geo, mat);
}

// Äá»‹nh nghÄ©a cÃ¡c báº£ng mÃ u trÃ´ng tá»± nhiÃªn cho cÃ¡c vÃ¬ sao
const starColors = [
    new THREE.Color(0xffffff), // Tráº¯ng tinh
    new THREE.Color(0xaadcff), // Tráº¯ng-xanh bÄƒng giÃ¡
    new THREE.Color(0xffffe0), // Tráº¯ng-vÃ ng áº¥m
    new THREE.Color(0xffd8b1)  // Cam nháº¡t
];

// BÃ¢y giá», chÃºng ta sá»­ dá»¥ng "nhÃ  mÃ¡y" Ä‘á»ƒ táº¡o 3 lá»›p sao riÃªng biá»‡t

// Lá»›p 1: CÃ¡c ngÃ´i sao xa nháº¥t, nhá» nháº¥t, vÃ  má» nháº¥t. ÄÃ¢y lÃ  lá»›p ná»n sÃ¢u tháº³m.
// Giáº£m sá»‘ lÆ°á»£ng sao Ä‘á»ƒ khá»Ÿi Ä‘á»™ng nhanh hÆ¡n
const farStars = createStarLayer({
    count: 2500,
    radius: 250,
    colors: [new THREE.Color(0xaadcff), new THREE.Color(0xffffff)],
    minSize: 0.5,
    maxSize: 1.5,
    opacity: 0.8
});

// Lá»›p 2: CÃ¡c ngÃ´i sao á»Ÿ cá»± ly trung bÃ¬nh, Ä‘a dáº¡ng mÃ u sáº¯c hÆ¡n.
const midStars = createStarLayer({
    count: 1500,
    radius: 180,
    colors: starColors,
    minSize: 1.0,
    maxSize: 2.5,
    opacity: 1.0
});

// Lá»›p 3: CÃ¡c ngÃ´i sao gáº§n nháº¥t, lá»›n nháº¥t, vÃ  sÃ¡ng nháº¥t. ChÃºng táº¡o Ä‘iá»ƒm nháº¥n.
const nearStars = createStarLayer({
    count: 500,
    radius: 120,
    colors: starColors,
    minSize: 1.5,
    maxSize: 4.0,
    opacity: 1.2
});

// ThÃªm táº¥t cáº£ cÃ¡c lá»›p vÃ o scene vÃ  quáº£n lÃ½ chÃºng cho hiá»‡u á»©ng fade-in khi báº¯t Ä‘áº§u
starLayers.push(farStars, midStars, nearStars);
starLayers.forEach(layer => {
    scene.add(layer);
    layer.visible = false;
    fadeObjects.push(layer);
    layer.userData.fadeStage = STAGE.STAR;
});


// --- Báº®T Äáº¦U: KHá»I MÃƒ Táº O Bá»¤I VÅ¨ TRá»¤ ---

const dustParticlesCount = 4500; // Giáº£m sá»‘ lÆ°á»£ng háº¡t bá»¥i Ä‘á»ƒ nháº¹ hÆ¡n khi khá»Ÿi Ä‘á»™ng
const dustPositions = new Float32Array(dustParticlesCount * 3);
const dustColors = new Float32Array(dustParticlesCount * 3);
const dustColor = new THREE.Color(0x4a148c); // MÃ u tÃ­m sáº«m huyá»n áº£o

for (let i = 0; i < dustParticlesCount; i++) {
    const i3 = i * 3;
    // PhÃ¢n bá»• ngáº«u nhiÃªn trong má»™t hÃ¬nh cáº§u lá»›n
    const phi = Math.acos((2 * Math.random()) - 1);
    const theta = Math.random() * Math.PI * 2;
    const radius = Math.random() * 200 + 50; // PhÃ¢n bá»• tá»« bÃ¡n kÃ­nh 50 Ä‘áº¿n 250

    dustPositions[i3] = radius * Math.cos(theta) * Math.sin(phi);
    dustPositions[i3 + 1] = radius * Math.sin(theta) * Math.sin(phi);
    dustPositions[i3 + 2] = radius * Math.cos(phi);

    // ThÃªm má»™t chÃºt biáº¿n thá»ƒ vá» mÃ u sáº¯c
    const colorVariation = Math.random() * 0.5 + 0.5;
    dustColors[i3] = dustColor.r * colorVariation;
    dustColors[i3 + 1] = dustColor.g * colorVariation;
    dustColors[i3 + 2] = dustColor.b * colorVariation;
}

const dustGeometry = new THREE.BufferGeometry();
dustGeometry.setAttribute('position', new THREE.BufferAttribute(dustPositions, 3));
dustGeometry.setAttribute('color', new THREE.BufferAttribute(dustColors, 3));

const dustMaterial = new THREE.PointsMaterial({
    size: 0.2,
    vertexColors: true,
    blending: THREE.AdditiveBlending, // Hiá»‡u á»©ng phÃ¡t sÃ¡ng
    transparent: true,
    opacity: 0.7
});

cosmicDust = new THREE.Points(dustGeometry, dustMaterial);
scene.add(cosmicDust);

// --- Káº¾T THÃšC: KHá»I MÃƒ Táº O Bá»¤I VÅ¨ TRá»¤ ---



// ChÃºng ta khÃ´ng cáº§n cÃ¡c biáº¿n cÅ© nÃ y ná»¯a, Ä‘áº·t chÃºng vá» giÃ¡ trá»‹ rá»—ng Ä‘á»ƒ trÃ¡nh nháº§m láº«n.
STAR_COUNT = 0;
starAlpha = null;
starPhase = null;
starGeo = null;

// --- Káº¾T THÃšC: KHá»I MÃƒ NÃ‚NG Cáº¤P Ná»€N TRá»œI SAO ---


const SHOOT_MAX = 10,
    TAIL_SEGMENTS = 260,
    TAIL_SPACING = .001,
    SHOOT_OUT_RADIUS = 350,
    SHOOT_POINTS = SHOOT_MAX * (1 + TAIL_SEGMENTS),
    shootPositions = new Float32Array(3 * SHOOT_MAX),
    shootVel = new Float32Array(3 * SHOOT_MAX),
    shootBirth = new Float32Array(SHOOT_MAX),
    shootLife = new Float32Array(SHOOT_MAX).fill(0),
    shootAlpha = new Float32Array(SHOOT_MAX).fill(0),
    shootSize = new Float32Array(SHOOT_MAX);
for (let t = 0; t < SHOOT_MAX; t++) shootSize[t] = 3;
const tailPositions = new Float32Array(3 * SHOOT_POINTS),
    tailColors = new Float32Array(3 * SHOOT_POINTS),
    tailSizes = new Float32Array(SHOOT_POINTS),
    tailAlphas = new Float32Array(SHOOT_POINTS).fill(0);
for (let t = 0; t < SHOOT_MAX; t++) {
    tailSizes[t * (TAIL_SEGMENTS + 1)] = 6;
    for (let e = 1; e <= TAIL_SEGMENTS; e++) {
        const a = t * (TAIL_SEGMENTS + 1) + e,
            o = 1 - e / TAIL_SEGMENTS;
        tailSizes[a] = 4 * o;
        const s = 3 * a;
        tailColors[s] = .7 * o, tailColors[s + 1] = .8 * o, tailColors[s + 2] = 1 * o
    }
}
for (let t = 0; t < SHOOT_MAX; t++) {
    const e = t * (TAIL_SEGMENTS + 1) * 3;
    tailColors[e] = 1, tailColors[e + 1] = 1, tailColors[e + 2] = 1
}
const tailGeo = new THREE.BufferGeometry;
tailGeo.setAttribute("position", new THREE.BufferAttribute(tailPositions, 3).setUsage(THREE.DynamicDrawUsage)), tailGeo.setAttribute("color", new THREE.BufferAttribute(tailColors, 3)), tailGeo.setAttribute("size", new THREE.BufferAttribute(tailSizes, 1)), tailGeo.setAttribute("alpha", new THREE.BufferAttribute(tailAlphas, 1).setUsage(THREE.DynamicDrawUsage));
const tailMat = makeMat({
    map: circleTexture,
    blending: THREE.AdditiveBlending,
    depthWrite: !1,
    alphaSupport: !0,
    vertexColors: !0,
    opacity: 2,
    sizeAttenuation: !1
});
tailMat.onBeforeCompile = function (t) {
    t.vertexShader = t.vertexShader.replace("uniform float size;", "attribute float size; attribute float alpha; varying float vAlpha;"), t.vertexShader = t.vertexShader.replace("#include <project_vertex>", "#include <project_vertex>\n  vAlpha = alpha;"), t.fragmentShader = t.fragmentShader.replace("void main() {", "varying float vAlpha;\nvoid main(){"), t.fragmentShader = t.fragmentShader.replace("gl_FragColor = vec4( outgoingLight, diffuseColor.a );", "gl_FragColor = vec4( outgoingLight, diffuseColor.a * vAlpha );")
};
const shootingStars = new THREE.Points(tailGeo, tailMat);
scene.add(shootingStars), shootingStars.userData.fadeStage = STAGE.SHOOT;
let nextShootTime = 0;

function triggerSceneActivation(t) {
    heartbeatEnabled || (heartbeatEnabled = !0, setupImageObjectPool(), lastImageSpawnTime = 0, imageSpawnQueue.length = 0, currentImageIndex = 0, lastStatusLogTime = 0, nextIndependentSpawnTime = 0, independentImageSprites.forEach(t => {
        t && t.parent && t.parent.remove(t)
    }), independentImageSprites.length = 0,

        fadeObjects.forEach(t => {
            t && (t.visible = !0, t.traverse?.(t => {
                const e = t.material;
                e && (t.material && void 0 === t.userData.baseOpacity && (t.userData.baseOpacity = t.material.opacity ?? 1), e.opacity = 0)
            }))
        }), revealStart = clock.getElapsedTime(), cameraAnimationStart = clock.getElapsedTime(), userHasMovedCamera && (CAMERA_START_POSITION = {
            x: camera.position.x,
            y: camera.position.y,
            z: camera.position.z
        }))
}

fadeObjects.push(streamHeart, shootingStars), [streamHeart, shootingStars].forEach(t => {
    t && (t.visible = !1, t.traverse?.(t => {
        t.material && void 0 === t.userData.baseOpacity && (t.userData.baseOpacity = t.material.opacity ?? 1)
    }))
}), renderer.domElement.addEventListener("pointerdown", (event) => {
    createHeartExplosion(event);
});

// Tá»± Ä‘á»™ng kÃ­ch hoáº¡t hiá»‡u á»©ng hÃ¬nh áº£nh ngay khi táº£i xong
triggerSceneActivation();
let lastTouchEnd = 0;
document.addEventListener("touchend", function (t) {
    const e = (new Date).getTime();
    e - lastTouchEnd <= 300 && t.preventDefault(), lastTouchEnd = e
}, !1), document.addEventListener("gesturestart", function (t) {
    t.preventDefault()
}, {
    passive: !1
}), document.addEventListener("gesturechange", function (t) {
    t.preventDefault()
}, {
    passive: !1
}), document.addEventListener("gestureend", function (t) {
    t.preventDefault()
}, {
    passive: !1
}), mainAnimationLoop(), scene.add(staticBottomHeart), [staticTopHeart].forEach(t => {
    t && (t.visible = !1, t.userData.fadeStage = STAGE.HEART, fadeObjects.push(t))
}), controls.addEventListener("change", () => {
    userHasMovedCamera || (CAMERA_START_POSITION = {
        x: camera.position.x,
        y: camera.position.y,
        z: camera.position.z
    }, userHasMovedCamera = !0)
});
