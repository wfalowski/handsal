export const locales = ["en", "pl"] as const;

/** Public repository. `SITE_GITHUB_URL` overrides this at build time. */
export const githubUrl = (
  process.env.SITE_GITHUB_URL ?? "https://github.com/wfalowski/handsal"
).replace(/\/$/, "");

export const authorUrl = "https://falowski.dev";

export type Locale = (typeof locales)[number];

const en = {
  language: "Language",
  page: "Page",
  skip: "Skip to content",
  whyNav: "Why",
  how: "How it works",
  runNav: "Run",
  docs: "Docs",
  docsOverview: "Overview",
  docsSdk: "Protect an API",
  docsApi: "Management API",
  source: "Source",
  footer: "Handsal. Self-hosted OAuth for services.",
  madeBy: "Made with love by",
  integration: "Integration guide",
  deployment: "Deployment guide",
  metaTitle: "Handsal — Authorization for machines",
  description:
    "Handsal is a self-hosted OAuth 2.0 server for services and AI agents. Each tenant has its own issuer. Every token names one audience and expires.",
  heroTitle: "Authorization, for machines.",
  lead: "A self-hosted OAuth 2.0 server. Your service asks, Handsal signs a token for one audience, and the token expires. An agent waits when a person has to say yes.",
  run: "Run it",
  callLink: "How a call works",
  useTitle: "What it is for.",
  cases: [
    {
      scene: "billing / orders",
      title: "A service calls another.",
      body: "Billing needs orders:read and nothing beside it. The token names the orders API. A token minted for the warehouse is refused.",
    },
    {
      scene: "agent / refunds",
      title: "An agent waits for a person.",
      body: "The agent proves itself with a private key, so the secret never sits in a prompt. A read can be granted outright. A refund waits for a person, and the token lasts five minutes.",
    },
    {
      scene: "acme / globex",
      title: "Each team has its own issuer.",
      body: "One server, many tenants. Each has its own keys, applications, and audiences. A token from one tenant does not verify against another.",
    },
  ],
  whyTitle: "Why Handsal.",
  whyLead:
    "Handsal is an Old Norse legal word. It is the joining of hands that made a bargain binding. The two parties said the terms aloud, and at least two witnesses saw and heard them. Before that, the deal was only talk.",
  whyWord: "handsal",
  whyGloss: "A neuter noun. Hand, and sal from selja, to hand something over.",
  whyNotes: [
    {
      title: "The clasp was the contract",
      body: "In the Icelandic Grágás and the old Norwegian laws, a sale of land, a pledge, or taking charge of someone else's property was finished by handsal. A broken handsal owed compensation.",
    },
    {
      title: "Spoken, and witnessed",
      body: "The parties, or a person they named, spoke a set formula. Two witnesses had to see the hands and hear the words. Some bargains were also announced at the assembly.",
    },
    {
      title: "A witness, for machines",
      body: "One side asks and the other answers. The token is the witness: one audience, only the scopes that were granted, and an expiry. English kept the word as handsel, the payment that seals a bargain.",
    },
  ],
  tokenCaption: "A token for tenant acme.",
  exp: "3600 seconds",
  shapeTitle: "What a token is allowed to be.",
  facts: [
    {
      title: "One audience",
      body: "The resource parameter is required. A token is issued for one API, with only the scopes that application was granted on it.",
    },
    {
      title: "Keys stay with the tenant",
      body: "Signing is ES256. The private key is encrypted at rest. Resource servers check the signature against that tenant's JWKS, or ask introspection.",
    },
    {
      title: "You can take it back",
      body: "Revoke one token, or every token for an application or a tenant. Introspection honors it at once. A server that only checks the signature waits until expiry, so the lifetime stays short. The default is one hour.",
    },
  ],
  callTitle: "How a call works.",
  callTabs: "Who is calling",
  tabService: "Service",
  tabAgent: "AI agent",
  serviceSteps: [
    {
      title: "Create a tenant.",
      body: "Its issuer is your public URL, then /t/, then the slug.",
    },
    {
      title: "Name the API and the caller.",
      body: "The resource has an audience and scopes. The application receives a client id and a secret. The secret is shown once.",
    },
    {
      title: "The service requests a token.",
      body: "Handsal checks the grant, signs with the tenant's active key, and returns a bearer token.",
    },
  ],
  agentSteps: [
    {
      title: "Register an agent.",
      body: "Give it a private key, so no shared secret can leak into a prompt. Tokens default to five minutes.",
    },
    {
      title: "Set the limits.",
      body: "How many scopes one token may carry, how many tokens an hour, and which networks may ask.",
    },
    {
      title: "The agent asks, and names the task.",
      body: "A scope that needs a person waits. Handsal signs after the approval, once. The token says the caller is an agent.",
    },
  ],
  runTitle: "One container. PostgreSQL beside it.",
  runBody:
    "Migrations run when the process starts. The admin UI is served from the same origin. You terminate TLS in a proxy and set the public URL to https.",
  listens: "The server listens on port 3000.",
  notFoundTitle: "This address is not here.",
  notFoundMeta: "Page not found — Handsal",
  notFoundDescription: "This address is not on the Handsal site.",
  notFoundBody: "This address does not match a page.",
  notFoundHome: "Go to the front page",
};

const pl: typeof en = {
  language: "Język",
  page: "Strona",
  skip: "Przejdź do treści",
  whyNav: "Dlaczego",
  how: "Jak to działa",
  runNav: "Uruchom",
  docs: "Dokumentacja",
  docsOverview: "Przegląd",
  docsSdk: "Zabezpiecz API",
  docsApi: "API zarządzania",
  source: "Źródło",
  footer: "Handsal. Własny OAuth dla usług.",
  madeBy: "Zrobione z miłością przez",
  integration: "Integracja",
  deployment: "Wdrożenie",
  metaTitle: "Handsal — Autoryzacja dla maszyn",
  description:
    "Handsal to własny serwer OAuth 2.0 dla usług i agentów AI. Każdy tenant ma swój issuer. Każdy token nazywa jednego odbiorcę i wygasa.",
  heroTitle: "Autoryzacja dla maszyn.",
  lead: "Własny serwer OAuth 2.0. Usługa prosi, Handsal podpisuje token dla jednego odbiorcy i token wygasa. Agent czeka, gdy musi zgodzić się człowiek.",
  run: "Uruchom",
  callLink: "Jak przebiega wywołanie",
  useTitle: "Po co to jest.",
  cases: [
    {
      scene: "billing / orders",
      title: "Usługa woła inną.",
      body: "Rozliczenia potrzebują orders:read i niczego więcej. Token nazywa API zamówień. Token wystawiony dla magazynu jest odrzucany.",
    },
    {
      scene: "agent / refunds",
      title: "Agent czeka na człowieka.",
      body: "Agent potwierdza się kluczem prywatnym, więc sekret nie leży w prompcie. Odczyt może przejść od razu. Zwrot czeka na człowieka, a token żyje pięć minut.",
    },
    {
      scene: "acme / globex",
      title: "Każdy zespół ma swój issuer.",
      body: "Jeden serwer, wielu tenantów. Każdy ma własne klucze, aplikacje i audience. Token jednego tenanta nie przechodzi u drugiego.",
    },
  ],
  whyTitle: "Dlaczego Handsal.",
  whyLead:
    "Handsal to staronordyckie słowo prawne. To złożenie dłoni, które czyniło umowę wiążącą. Strony wypowiadały warunki na głos, a co najmniej dwóch świadków widziało i słyszało. Wcześniej układ był tylko rozmową.",
  whyWord: "handsal",
  whyGloss: "Rzeczownik nijaki. Hand, dłoń, i sal od selja, przekazać coś komuś.",
  whyNotes: [
    {
      title: "Uścisk był umową",
      body: "W islandzkiej Grágás i w dawnym prawie norweskim sprzedaż ziemi, poręczenie albo oddanie cudzego mienia w opiekę kończyło się przez handsal. Zerwany handsal pociągał odszkodowanie.",
    },
    {
      title: "Wypowiedziany i zaświadczony",
      body: "Strony albo osoba, którą wskazały, mówiły ustaloną formułę. Dwóch świadków musiało widzieć dłonie i słyszeć słowa. Niektóre umowy ogłaszano też na wiecu.",
    },
    {
      title: "Świadek, dla maszyn",
      body: "Jedna strona prosi, druga odpowiada. Token jest świadkiem: jeden odbiorca, tylko przyznane zakresy i termin wygaśnięcia. Angielski zachował to słowo jako handsel, wpłatę, która pieczętuje układ.",
    },
  ],
  tokenCaption: "Token tenanta acme.",
  exp: "3600 sekund",
  shapeTitle: "Do czego token ma prawo.",
  facts: [
    {
      title: "Jeden odbiorca",
      body: "Parametr resource jest wymagany. Token jest wydawany dla jednego API i tylko tych zakresów, które ta aplikacja dostała na tym API.",
    },
    {
      title: "Klucze zostają u tenanta",
      body: "Podpis jest ES256. Klucz prywatny jest zaszyfrowany w spoczynku. Serwer zasobów sprawdza podpis w JWKS tego tenanta albo pyta o introspekcję.",
    },
    {
      title: "Możesz go unieważnić",
      body: "Unieważniasz jeden token albo wszystkie tokeny aplikacji lub tenanta. Introspekcja widzi to od razu. Serwer, który sprawdza tylko podpis, czeka do wygaśnięcia, więc czas życia zostaje krótki. Domyślnie jest to godzina.",
    },
  ],
  callTitle: "Jak przebiega wywołanie.",
  callTabs: "Kto woła",
  tabService: "Usługa",
  tabAgent: "Agent AI",
  serviceSteps: [
    {
      title: "Załóż tenanta.",
      body: "Jego issuer to publiczny adres, potem /t/, potem slug.",
    },
    {
      title: "Nazwij API i wywołującego.",
      body: "Zasób ma audience i zakresy. Aplikacja dostaje client id i sekret. Sekret widać raz.",
    },
    {
      title: "Usługa prosi o token.",
      body: "Handsal sprawdza grant, podpisuje aktywnym kluczem tenanta i zwraca token bearer.",
    },
  ],
  agentSteps: [
    {
      title: "Zarejestruj agenta.",
      body: "Daj mu klucz prywatny, żeby wspólny sekret nie wpadł do promptu. Tokeny domyślnie żyją pięć minut.",
    },
    {
      title: "Ustaw limity.",
      body: "Ile zakresów może nieść jeden token, ile tokenów na godzinę i z jakich sieci wolno prosić.",
    },
    {
      title: "Agent prosi i nazywa zadanie.",
      body: "Zakres, który wymaga człowieka, czeka. Handsal podpisuje po zgodzie, raz. Token mówi, że woła agent.",
    },
  ],
  runTitle: "Jeden kontener. PostgreSQL obok.",
  runBody:
    "Migracje ruszają przy starcie procesu. Panel administratora jest pod tym samym adresem. TLS kończysz w proxy i ustawiasz publiczny adres na https.",
  listens: "Serwer nasłuchuje na porcie 3000.",
  notFoundTitle: "Tego adresu tu nie ma.",
  notFoundMeta: "Nie ma takiej strony — Handsal",
  notFoundDescription: "Tego adresu nie ma na stronie Handsal.",
  notFoundBody: "Ten adres nie prowadzi do żadnej strony.",
  notFoundHome: "Wróć na początek",
};

export const messages = { en, pl };

export function homePath(locale: Locale): string {
  return locale === "en" ? "/" : "/pl";
}

/** `path` is the English path, starting with `/`. `/` is the landing page. */
export function localePath(locale: Locale, path: string): string {
  if (path === "/") return homePath(locale);
  return locale === "en" ? path : `/pl${path}`;
}
