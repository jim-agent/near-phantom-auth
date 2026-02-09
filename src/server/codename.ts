/**
 * Codename Generator
 * 
 * Generates anonymous codenames for HUMINT sources
 */

import { randomBytes } from 'crypto';

const NATO_PHONETIC = [
  'ALPHA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO', 'FOXTROT', 'GOLF', 'HOTEL',
  'INDIA', 'JULIET', 'KILO', 'LIMA', 'MIKE', 'NOVEMBER', 'OSCAR', 'PAPA',
  'QUEBEC', 'ROMEO', 'SIERRA', 'TANGO', 'UNIFORM', 'VICTOR', 'WHISKEY',
  'XRAY', 'YANKEE', 'ZULU'
];

const ADJECTIVES = [
  'SWIFT', 'SILENT', 'SHADOW', 'STEEL', 'STORM', 'FROST', 'CRIMSON', 'GOLDEN',
  'SILVER', 'IRON', 'DARK', 'BRIGHT', 'RAPID', 'GHOST', 'PHANTOM', 'ARCTIC',
  'DESERT', 'OCEAN', 'MOUNTAIN', 'FOREST', 'THUNDER', 'LIGHTNING', 'COSMIC'
];

const ANIMALS = [
  'FALCON', 'EAGLE', 'HAWK', 'WOLF', 'BEAR', 'LION', 'TIGER', 'PANTHER',
  'COBRA', 'VIPER', 'RAVEN', 'OWL', 'SHARK', 'DRAGON', 'PHOENIX', 'GRIFFIN',
  'LEOPARD', 'JAGUAR', 'LYNX', 'FOX', 'ORCA', 'RAPTOR', 'CONDOR'
];

export type CodenameStyle = 'nato-phonetic' | 'animals' | 'custom';

/**
 * Generate a random number suffix (1-99)
 */
function randomSuffix(): number {
  const bytes = randomBytes(1);
  return (bytes[0] % 99) + 1;
}

/**
 * Pick a random element from an array
 */
function randomPick<T>(array: T[]): T {
  const bytes = randomBytes(1);
  return array[bytes[0] % array.length];
}

/**
 * Generate NATO phonetic codename (e.g., ALPHA-7, BRAVO-42)
 */
export function generateNatoCodename(): string {
  const word = randomPick(NATO_PHONETIC);
  const num = randomSuffix();
  return `${word}-${num}`;
}

/**
 * Generate animal codename (e.g., SWIFT-FALCON-42)
 */
export function generateAnimalCodename(): string {
  const adj = randomPick(ADJECTIVES);
  const animal = randomPick(ANIMALS);
  const num = randomSuffix();
  return `${adj}-${animal}-${num}`;
}

/**
 * Generate codename based on style
 */
export function generateCodename(style: CodenameStyle = 'nato-phonetic'): string {
  switch (style) {
    case 'nato-phonetic':
      return generateNatoCodename();
    case 'animals':
      return generateAnimalCodename();
    default:
      return generateNatoCodename();
  }
}

/**
 * Check if a codename format is valid
 */
export function isValidCodename(codename: string): boolean {
  // NATO: WORD-NN
  const natoPattern = /^[A-Z]+-\d{1,2}$/;
  // Animal: WORD-WORD-NN
  const animalPattern = /^[A-Z]+-[A-Z]+-\d{1,2}$/;
  
  return natoPattern.test(codename) || animalPattern.test(codename);
}
