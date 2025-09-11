import pygame, sys, random, time, os, math, json

def resource_path(relative_path):
    """Devuelve la ruta correcta al recurso tanto en .exe como en .py"""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# Archivos
RECORD_FILE = "record.json"
STORE_FILE = "store.json"

# Configuración
ANCHO, ALTO = 1200, 840
FPS = 60
VIDAS_JUGADOR = 5
VIDA_ENEMIGO = 1
DAÑO_PROYECTIL = 1

pygame.init()
pantalla = pygame.display.set_mode((ANCHO, ALTO))
pygame.display.set_caption("Survivor Mage")
clock = pygame.time.Clock()
fuente = pygame.font.SysFont("Arial", 24)
font_small = pygame.font.SysFont("Arial", 32)
font_big = pygame.font.SysFont("Arial", 48)

# Utilidades de archivos
def cargar_record():
    if os.path.exists(RECORD_FILE):
        try:
            with open(RECORD_FILE, "r") as f:
                data = json.load(f)
                return int(data.get("record", 0))
        except:
            return 0
    return 0

def guardar_record(record):
    with open(RECORD_FILE, "w") as f:
        json.dump({"record": record}, f)

def cargar_store():
    puntos = 0
    armas = ["normal"]
    if os.path.exists(STORE_FILE):
        with open(STORE_FILE, "r") as f:
            try:
                data = json.load(f)
                puntos = int(data.get("puntos", 0))
                armas = data.get("armas", ["normal"])
            except:
                pass
    return puntos, armas

def guardar_store(puntos, armas):
    with open(STORE_FILE, "w") as f:
        json.dump({"puntos": puntos, "armas": armas}, f)

# Clases
class Player:
    def __init__(self, x, y, idle_path, num_frames=8, scale=2, shot_type="normal", max_shots=5, vidas=VIDAS_JUGADOR):
        self.frames = self.load_spritesheet(idle_path, num_frames, scale)
        self.frame_index = 0
        self.image = self.frames[self.frame_index]
        self.rect = self.image.get_rect(center=(x, y))
        self.hitbox = pygame.Rect(0, 0, self.rect.width // 4, self.rect.height // 4)
        self.hitbox.center = self.rect.center
        self.speed = 5
        self.vidas = vidas
        self.projectiles = []
        self.max_shots = max_shots
        self.shots_available = self.max_shots
        self.anim_timer = 0
        self.shot_type = shot_type

    def load_spritesheet(self, path, num_frames, scale):
        sheet = pygame.image.load(path).convert_alpha()
        frame_width = sheet.get_width() // num_frames
        frames = []
        for i in range(num_frames):
            frame = sheet.subsurface(pygame.Rect(i*frame_width, 0, frame_width, sheet.get_height()))
            frame = pygame.transform.scale(frame, (frame.get_width()*scale, frame.get_height()*scale))
            frames.append(frame)
        return frames

    def handle_input(self, keys):
        if keys[pygame.K_LEFT] or keys[pygame.K_a]:
            self.rect.x -= self.speed
        if keys[pygame.K_RIGHT] or keys[pygame.K_d]:
            self.rect.x += self.speed
        if keys[pygame.K_UP] or keys[pygame.K_w]:
            self.rect.y -= self.speed
        if keys[pygame.K_DOWN] or keys[pygame.K_s]:
            self.rect.y += self.speed

    def shoot(self, target_pos):
        if self.shots_available > 0:
            shots = []
            # Normal y penetrador
            if self.shot_type == "normal" or self.shot_type == "penetrador":
                shots = [Projectile(self.rect.centerx, self.rect.centery, target_pos, penetrador=(self.shot_type=="penetrador"))]
            # Doble
            elif self.shot_type == "doble":
                shots = [
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0], target_pos[1]-20)),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0], target_pos[1]+20))
                ]
            # Triple
            elif self.shot_type == "triple":
                shots = [
                    Projectile(self.rect.centerx, self.rect.centery, target_pos),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]+20, target_pos[1]-20)),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]-20, target_pos[1]+20))
                ]
            # Quintuple
            elif self.shot_type == "quintuple":
                shots = [
                    Projectile(self.rect.centerx, self.rect.centery, target_pos),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]+30, target_pos[1]-30)),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]-30, target_pos[1]+30)),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]+30, target_pos[1]+30)),
                    Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]-30, target_pos[1]-30))
                ]
            # Ráfaga
            elif self.shot_type == "rafaga":
                for angle in range(-30, 31, 15):
                    shots.append(Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]+angle, target_pos[1]), penetrador=False))
            # Explosivo
            elif self.shot_type == "explosivo":
                shots = [Projectile(self.rect.centerx, self.rect.centery, target_pos, explosivo=True)]
            # Láser
            elif self.shot_type == "laser":
                shots = [Projectile(self.rect.centerx, self.rect.centery, target_pos, laser=True)]
            # Boomerang
            elif self.shot_type == "boomerang":
                shots = [Projectile(self.rect.centerx, self.rect.centery, target_pos, boomerang=True)]
            # Arco iris
            elif self.shot_type == "arcoiris":
                for color_angle in range(0, 360, 60):
                    shots.append(Projectile(self.rect.centerx, self.rect.centery, (target_pos[0]+color_angle//6, target_pos[1]+color_angle//6), arcoiris=True))
            for s in shots:
                self.projectiles.append(s)
            self.shots_available -= 1

    def update(self):
        if self.shots_available < self.max_shots:
            self.shots_available += 0.02
            if self.shots_available > self.max_shots:
                self.shots_available = self.max_shots
        self.anim_timer += 1
        if self.anim_timer >= 10:
            self.frame_index = (self.frame_index + 1) % len(self.frames)
            self.image = self.frames[self.frame_index]
            self.anim_timer = 0
        if self.rect.left < 0: self.rect.left = 0
        if self.rect.right > ANCHO: self.rect.right = ANCHO
        if self.rect.top < 0: self.rect.top = 0
        if self.rect.bottom > ALTO: self.rect.bottom = ALTO
        self.hitbox.center = self.rect.center
        for p in self.projectiles[:]:
            p.update()
            if not pantalla.get_rect().colliderect(p.rect):
                self.projectiles.remove(p)

    def draw(self, surface):
        surface.blit(self.image, self.rect)
        for p in self.projectiles:
            p.draw(surface)

class Projectile:
    skeleton_img = None

    @staticmethod
    def load_skeleton():
        if Projectile.skeleton_img is None:
            try:
                img = pygame.image.load("Skeleton Walk.gif").convert_alpha()
                Projectile.skeleton_img = pygame.transform.scale(img, (32,32))
            except:
                Projectile.skeleton_img = None

    def __init__(self, x, y, target_pos, penetrador=False, explosivo=False, laser=False, boomerang=False, arcoiris=False):
        Projectile.load_skeleton()
        self.rect = pygame.Rect(x, y, 32, 32)
        self.speed = 8
        self.penetrador = penetrador
        self.explosivo = explosivo
        self.laser = laser
        self.boomerang = boomerang
        self.arcoiris = arcoiris
        self.color = (200,255,200)
        if self.explosivo:
            self.color = (255,100,0)
        elif self.laser:
            self.color = (100,255,255)
        elif self.boomerang:
            self.color = (255,255,100)
        elif self.arcoiris:
            self.color = random.choice([(255,0,0),(255,255,0),(0,255,0),(0,255,255),(0,0,255),(255,0,255)])
        dx, dy = target_pos[0] - x, target_pos[1] - y
        dist = math.hypot(dx, dy)
        if dist == 0:
            dist = 1
        self.dx = dx / dist
        self.dy = dy / dist
        self.ticks = 0

    def update(self):
        self.ticks += 1
        # Animaciones especiales
        if self.boomerang:
            if self.ticks < 20:
                self.rect.x += int(self.dx * self.speed)
                self.rect.y += int(self.dy * self.speed)
            else:
                self.rect.x -= int(self.dx * self.speed)
                self.rect.y -= int(self.dy * self.speed)
        elif self.laser:
            self.rect.x += int(self.dx * self.speed * 2)
            self.rect.y += int(self.dy * self.speed * 2)
        else:
            self.rect.x += int(self.dx * self.speed)
            self.rect.y += int(self.dy * self.speed)

    def draw(self, surface):
        if Projectile.skeleton_img:
            img_rect = Projectile.skeleton_img.get_rect(center=self.rect.center)
            surface.blit(Projectile.skeleton_img, img_rect)
        else:
            color = self.color
            pulse = 5 + int(2 * math.sin(pygame.time.get_ticks()/100 + self.rect.x))
            if self.penetrador:
                color = (255,200,50)
            pygame.draw.circle(surface, color, self.rect.center, pulse)
            if self.laser:
                pygame.draw.line(surface, color, self.rect.center, (self.rect.centerx+self.dx*30, self.rect.centery+self.dy*30), 3)
            if self.explosivo:
                pygame.draw.circle(surface, (255,150,0), self.rect.center, 10 + pulse//2, 2)
            if self.arcoiris:
                pygame.draw.circle(surface, color, self.rect.center, 7 + pulse//2, 2)

class Enemy:
    skeleton_img = None
    @staticmethod
    def load_skeleton():
        if Enemy.skeleton_img is None:
            try:
                img = pygame.image.load("Skeleton Walk.gif").convert_alpha()
                Enemy.skeleton_img = pygame.transform.scale(img, (40,40))
            except:
                Enemy.skeleton_img = None

    def __init__(self):
        Enemy.load_skeleton()
        side = random.choice(["top","bottom","left","right"])
        if side == "top": self.rect = pygame.Rect(random.randint(0, ANCHO), 0, 40, 40)
        elif side == "bottom": self.rect = pygame.Rect(random.randint(0, ANCHO), ALTO-40, 40, 40)
        elif side == "left": self.rect = pygame.Rect(0, random.randint(0, ALTO), 40, 40)
        else: self.rect = pygame.Rect(ANCHO-40, random.randint(0, ALTO), 40, 40)
        self.speed = 2
        self.vida = VIDA_ENEMIGO

    def update(self, player_rect):
        dx, dy = player_rect.centerx - self.rect.centerx, player_rect.centery - self.rect.centery
        dist = max(1, (dx**2 + dy**2)**0.5)
        self.rect.x += int(self.speed * dx / dist)
        self.rect.y += int(self.speed * dy / dist)

    def draw(self, surface):
        if Enemy.skeleton_img:
            img_rect = Enemy.skeleton_img.get_rect(center=self.rect.center)
            surface.blit(Enemy.skeleton_img, img_rect)
        else:
            pygame.draw.circle(surface, (200,50,50), self.rect.center, self.rect.width//2)

# Menú principal y tienda
def mostrar_menu(puntos):
    pantalla.fill((20,20,40))
    # Fondo animado simple
    for i in range(0, ANCHO, 40):
        pygame.draw.line(pantalla, (40,40,80), (i,0), (i,ALTO), 1)        # Menú principal
        def mostrar_menu(puntos):
            t = pygame.time.get_ticks() // 10
            base = 20 + int(20 * (1 + math.sin(t/30)))
            pantalla.fill((base,base,base+20))
            for i in range(0, ANCHO, 40):
                pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
            for j in range(0, ALTO, 40):
                pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
            txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
            pantalla.blit(txt, (ANCHO//2-300, 120))
            # ...resto del código...            # Menú principal
            def mostrar_menu(puntos):
                t = pygame.time.get_ticks() // 10
                base = 20 + int(20 * (1 + math.sin(t/30)))
                pantalla.fill((base,base,base+20))
                for i in range(0, ANCHO, 40):
                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                for j in range(0, ALTO, 40):
                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                pantalla.blit(txt, (ANCHO//2-300, 120))
                # ...resto del código...                # Menú principal
                def mostrar_menu(puntos):
                    t = pygame.time.get_ticks() // 10
                    base = 20 + int(20 * (1 + math.sin(t/30)))
                    pantalla.fill((base,base,base+20))
                    for i in range(0, ANCHO, 40):
                        pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                    for j in range(0, ALTO, 40):
                        pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                    txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                    pantalla.blit(txt, (ANCHO//2-300, 120))
                    # ...resto del código...                    # Menú principal
                    def mostrar_menu(puntos):
                        t = pygame.time.get_ticks() // 10
                        base = 20 + int(20 * (1 + math.sin(t/30)))
                        pantalla.fill((base,base,base+20))
                        for i in range(0, ANCHO, 40):
                            pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                        for j in range(0, ALTO, 40):
                            pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                        txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                        pantalla.blit(txt, (ANCHO//2-300, 120))
                        # ...resto del código...                        # Menú principal
                        def mostrar_menu(puntos):
                            t = pygame.time.get_ticks() // 10
                            base = 20 + int(20 * (1 + math.sin(t/30)))
                            pantalla.fill((base,base,base+20))
                            for i in range(0, ANCHO, 40):
                                pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                            for j in range(0, ALTO, 40):
                                pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                            txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                            pantalla.blit(txt, (ANCHO//2-300, 120))
                            # ...resto del código...                            # Menú principal
                            def mostrar_menu(puntos):
                                t = pygame.time.get_ticks() // 10
                                base = 20 + int(20 * (1 + math.sin(t/30)))
                                pantalla.fill((base,base,base+20))
                                for i in range(0, ANCHO, 40):
                                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                                for j in range(0, ALTO, 40):
                                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                                txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                                pantalla.blit(txt, (ANCHO//2-300, 120))
                                # ...resto del código...                                # Menú principal
                                def mostrar_menu(puntos):
                                    t = pygame.time.get_ticks() // 10
                                    base = 20 + int(20 * (1 + math.sin(t/30)))
                                    pantalla.fill((base,base,base+20))
                                    for i in range(0, ANCHO, 40):
                                        pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                                    for j in range(0, ALTO, 40):
                                        pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                                    txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                                    pantalla.blit(txt, (ANCHO//2-300, 120))
                                    # ...resto del código...                                    # Menú principal
                                    def mostrar_menu(puntos):
                                        t = pygame.time.get_ticks() // 10
                                        base = 20 + int(20 * (1 + math.sin(t/30)))
                                        pantalla.fill((base,base,base+20))
                                        for i in range(0, ANCHO, 40):
                                            pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                                        for j in range(0, ALTO, 40):
                                            pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                                        txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                                        pantalla.blit(txt, (ANCHO//2-300, 120))
                                        # ...resto del código...                                        # Menú principal
                                        def mostrar_menu(puntos):
                                            t = pygame.time.get_ticks() // 10
                                            base = 20 + int(20 * (1 + math.sin(t/30)))
                                            pantalla.fill((base,base,base+20))
                                            for i in range(0, ANCHO, 40):
                                                pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                                            for j in range(0, ALTO, 40):
                                                pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                                            txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                                            pantalla.blit(txt, (ANCHO//2-300, 120))
                                            # ...resto del código...                                            # Menú principal
                                            def mostrar_menu(puntos):
                                                t = pygame.time.get_ticks() // 10
                                                base = 20 + int(20 * (1 + math.sin(t/30)))
                                                pantalla.fill((base,base,base+20))
                                                for i in range(0, ANCHO, 40):
                                                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (i,0), (i,ALTO), 1)
                                                for j in range(0, ALTO, 40):
                                                    pygame.draw.line(pantalla, (base+20,base+20,base+60), (0,j), (ANCHO,j), 1)
                                                txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
                                                pantalla.blit(txt, (ANCHO//2-300, 120))
                                                # ...resto del código...
    for j in range(0, ALTO, 40):
        pygame.draw.line(pantalla, (40,40,80), (0,j), (ANCHO,j), 1)
    txt = font_big.render("SURVIVOR MAGE", True, (255,255,100))
    pantalla.blit(txt, (ANCHO//2-300, 120))
    opciones = ["Jugar", "Tienda", "Salir"]
    for i, op in enumerate(opciones):
        color = (100,255,100) if i==0 else (255,255,255)
        surf = font_small.render(f"{i+1}. {op}", True, color)
        # Sombra
        pantalla.blit(font_small.render(f"{i+1}. {op}", True, (0,0,0)), (ANCHO//2-102, 302+i*60))
        pantalla.blit(surf, (ANCHO//2-100, 300+i*60))
    pantalla.blit(fuente.render(f"Puntos: {puntos}", True, (255,255,0)), (ANCHO//2-100, 200))
    pygame.display.flip()

def mostrar_tienda(puntos, armas_compradas):
    pantalla.fill((30,30,60))
    pantalla.blit(font_big.render("TIENDA DE ARMAS", True, (255,200,100)), (ANCHO//2-250, 60))
    tienda = [
        ("Disparo penetrador", "penetrador", 10000, "permanente"),
        ("Disparo doble", "doble", 15000, "permanente"),
        ("Disparo triple", "triple", 20000, "permanente"),
        ("Disparo quintuple", "quintuple", 30000, "permanente"),
        ("Disparo ráfaga", "rafaga", 50000, "permanente"),
        ("Disparo explosivo", "explosivo", 80000, "permanente"),
        ("Disparo láser", "laser", 120000, "permanente"),
        ("Disparo boomerang", "boomerang", 200000, "permanente"),
        ("Disparo arco iris", "arcoiris", 500000, "permanente"),
        ("+1 vida", "vida", 5000, "temporal"),
    ]
    for i, (nombre, clave, precio, tipo) in enumerate(tienda):
        comprado = clave in armas_compradas if tipo=="permanente" else False
        color = (100,255,100) if comprado else (255,255,255)
        surf = font_small.render(f"{i+1}. {nombre} - {precio} pts [{tipo}]", True, color)
        pantalla.blit(font_small.render(f"{i+1}. {nombre} - {precio} pts [{tipo}]", True, (0,0,0)), (ANCHO//2-252, 182+i*40))
        pantalla.blit(surf, (ANCHO//2-250, 180+i*40))
    pantalla.blit(fuente.render(f"Puntos: {puntos}", True, (255,255,0)), (ANCHO//2-100, 120))
    pantalla.blit(fuente.render("Presiona número para comprar, ESC para volver", True, (200,200,255)), (ANCHO//2-250, 520))
    pygame.display.flip()

def comprar_en_tienda(opcion, puntos, armas_compradas, vidas_extra):
    tienda = [
        ("Disparo penetrador", "penetrador", 10000, "permanente"),
        ("Disparo doble", "doble", 15000, "permanente"),
        ("Disparo triple", "triple", 20000, "permanente"),
        ("Disparo quintuple", "quintuple", 30000, "permanente"),
        ("Disparo ráfaga", "rafaga", 50000, "permanente"),
        ("Disparo explosivo", "explosivo", 80000, "permanente"),
        ("Disparo láser", "laser", 120000, "permanente"),
        ("Disparo boomerang", "boomerang", 200000, "permanente"),
        ("Disparo arco iris", "arcoiris", 500000, "permanente"),
        ("+1 vida", "vida", 5000, "temporal"),
    ]
    if opcion < 1 or opcion > len(tienda):
        return puntos, armas_compradas, vidas_extra
    nombre, clave, precio, tipo = tienda[opcion-1]
    if tipo == "permanente":
        if clave not in armas_compradas and puntos >= precio:
            armas_compradas.append(clave)
            puntos -= precio
    elif tipo == "temporal":
        if puntos >= precio:
            vidas_extra += 1
            puntos -= precio
    return puntos, armas_compradas, vidas_extra

# Juego principal
def iniciar_juego(puntos, armas_compradas, vidas_extra):
    record = cargar_record()
    game_over = False
    # Elige el arma más cara desbloqueada
    armas_orden = ["arcoiris","boomerang","laser","explosivo","rafaga","quintuple","triple","doble","penetrador","normal"]
    arma_inicial = "normal"
    for arma in armas_orden:
        if arma in armas_compradas:
            arma_inicial = arma
            break
    player = Player(ANCHO//2, ALTO//2, "Idle.png", num_frames=8, scale=1,
                   shot_type=arma_inicial,
                   max_shots=5, vidas=VIDAS_JUGADOR+vidas_extra)
    enemies = []
    spawn_timer = 0
    start_time = time.time()
    last_difficulty_time = start_time
    enemies_per_spawn = 1
    pause_event_time = start_time
    paused = False
    pause_option = None
    mejora_actual = None
    puntos_ganados = 0
    final_time = 0
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                guardar_store(puntos+puntos_ganados, armas_compradas)
                pygame.quit(); sys.exit()
            if event.type == pygame.KEYDOWN:
                if game_over:
                    if event.key == pygame.K_SPACE:
                        guardar_store(puntos+puntos_ganados, armas_compradas)
                        return puntos+puntos_ganados, armas_compradas
                elif paused:
                    if event.key == pygame.K_1:
                        mejora_actual[0][1]()
                        paused = False
                        pause_option = None
                        pause_event_time = time.time()
                        mejora_actual = None
                    elif event.key == pygame.K_2:
                        mejora_actual[1][1]()
                        paused = False
                        pause_option = None
                        pause_event_time = time.time()
                        mejora_actual = None
                else:
                    if event.key == pygame.K_SPACE:
                        mouse_pos = pygame.mouse.get_pos()
                        player.shoot(mouse_pos)
            if event.type == pygame.MOUSEBUTTONDOWN and not game_over and not paused:
                if event.button == 1:
                    mouse_pos = pygame.mouse.get_pos()
                    player.shoot(mouse_pos)

        tiempo_actual = time.time()
        # Mostrar menú de mejora cada 15 segundos
        if not game_over and not paused and (tiempo_actual - pause_event_time) >= 15:
            paused = True
            pause_option = True
            mejora_actual = None

        # ...existing code...
        if paused:
            opciones = [
                ("+1 vida", lambda: setattr(player, "vidas", player.vidas+1)),
                ("+5 disparos máximos", lambda: setattr(player, "max_shots", player.max_shots+5)),
                ("Disparo penetrador", lambda: setattr(player, "shot_type", "penetrador")),
                ("Disparo doble", lambda: setattr(player, "shot_type", "doble")),
                ("Disparo triple", lambda: setattr(player, "shot_type", "triple")),
                ("Disparo quintuple", lambda: setattr(player, "shot_type", "quintuple")),
                ("Disparo ráfaga", lambda: setattr(player, "shot_type", "rafaga")),
                ("Disparo explosivo", lambda: setattr(player, "shot_type", "explosivo")),
                ("Disparo láser", lambda: setattr(player, "shot_type", "laser")),
                ("Disparo boomerang", lambda: setattr(player, "shot_type", "boomerang")),
                ("Disparo arco iris", lambda: setattr(player, "shot_type", "arcoiris")),
            ]
            if mejora_actual is None or len(mejora_actual) != 2:
                mejora_actual = random.sample(opciones, 2)
        # Dibuja el menú de mejora SIEMPRE que esté pausado, con animación simple
        if paused:
            pantalla.fill((30,30,70))
            for i in range(0, ANCHO, 60):
                pygame.draw.line(pantalla, (60,60,120), (i,0), (i,ALTO), 1)
            for j in range(0, ALTO, 60):
                pygame.draw.line(pantalla, (60,60,120), (0,j), (ANCHO,j), 1)
            txt_pause = font_big.render("¡PAUSA! Elige una opción:", True, (255,255,255))
            pantalla.blit(txt_pause, (ANCHO//2-250, ALTO//2-120))
            txt_opt1 = font_small.render(f"1: {mejora_actual[0][0]}", True, (100,255,100))
            pantalla.blit(txt_opt1, (ANCHO//2-120, ALTO//2-30))
            txt_opt2 = font_small.render(f"2: {mejora_actual[1][0]}", True, (100,200,255))
            pantalla.blit(txt_opt2, (ANCHO//2-120, ALTO//2+30))
            txt_info = fuente.render("Presiona 1 o 2 para elegir", True, (255,255,255))
            pantalla.blit(txt_info, (ANCHO//2-120, ALTO//2+90))
            pygame.display.flip()
            clock.tick(FPS)
            continue
        if not game_over and not paused:
            keys = pygame.key.get_pressed()
            player.handle_input(keys)
            player.update()
            if tiempo_actual - last_difficulty_time >= 10:
                for e in enemies:
                    e.speed += 0.2
                enemies_per_spawn += 1
                last_difficulty_time = tiempo_actual
            spawn_timer += 1
            if spawn_timer > FPS:
                for _ in range(enemies_per_spawn):
                    enemies.append(Enemy())
                spawn_timer = 0
            for e in enemies[:]:
                e.update(player.rect)
                for p in player.projectiles[:]:
                    if e.rect.colliderect(p.rect):
                        e.vida -= DAÑO_PROYECTIL
                        if not getattr(p, "penetrador", False):
                            player.projectiles.remove(p)
                        if e.vida <= 0:
                            if e in enemies:
                                enemies.remove(e)
                                puntos_ganados += 5
                            break
                if e.rect.colliderect(player.hitbox):
                    player.vidas -= 1
                    if e in enemies:
                        enemies.remove(e)
                    if player.vidas <= 0:
                        game_over = True
                        final_time = int(time.time() - start_time)
                        if final_time > record:
                            record = final_time
                            guardar_record(record)
        pantalla.fill((20,20,30))
        player.draw(pantalla)
        for e in enemies:
            e.draw(pantalla)
        if not game_over:
            tiempo = int(time.time() - start_time)
        else:
            tiempo = final_time
        txt = fuente.render(f"Tiempo: {tiempo}s", True, (255,255,255))
        pantalla.blit(txt, (20,20))
        txt_vidas = fuente.render(f"Vidas: {player.vidas}", True, (255,255,255))
        pantalla.blit(txt_vidas, (20,50))
        txt_record = fuente.render(f"Record: {record}s", True, (255,255,0))
        pantalla.blit(txt_record, (20,80))
        txt_shots = fuente.render(f"Disparos: {int(player.shots_available)}/{player.max_shots}", True, (100,255,255))
        pantalla.blit(txt_shots, (20,110))
        pantalla.blit(fuente.render(f"Puntos: {puntos+puntos_ganados}", True, (255,255,0)), (20,140))
        if game_over:
            txt = font_big.render(f"GAME OVER - Sobreviviste {tiempo}s", True, (255,100,100))
            pantalla.blit(txt, (ANCHO//2-300, ALTO//2))
            txt2 = font_small.render("Presiona ESPACIO para reiniciar", True, (255,255,255))
            pantalla.blit(txt2, (ANCHO//2-220, ALTO//2+60))
            txt3 = font_small.render(f"Record: {record}s", True, (255,255,0))
            pantalla.blit(txt3, (ANCHO//2-120, ALTO//2+110))
        pygame.display.flip()
        clock.tick(FPS)

# Bucle principal
def main():
    puntos, armas_compradas = cargar_store()
    vidas_extra = 0
    estado = "menu"
    while True:
        if estado == "menu":
            mostrar_menu(puntos)
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit(); sys.exit()
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_1:
                        estado = "juego"
                    elif event.key == pygame.K_2:
                        estado = "tienda"
                    elif event.key == pygame.K_3:
                        pygame.quit(); sys.exit()
        elif estado == "tienda":
            mostrar_tienda(puntos, armas_compradas)
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit(); sys.exit()
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        estado = "menu"
                    elif event.key in [pygame.K_1, pygame.K_2, pygame.K_3, pygame.K_4, pygame.K_5]:
                        opcion = int(event.unicode)
                        puntos, armas_compradas, vidas_extra = comprar_en_tienda(opcion, puntos, armas_compradas, vidas_extra)
                        guardar_store(puntos, armas_compradas)
        elif estado == "juego":
            puntos, armas_compradas = iniciar_juego(puntos, armas_compradas, vidas_extra)
            vidas_extra = 0
            estado = "menu"

if __name__ == "__main__":
    main()