const phones: {
  [k: string]: {
    customerId: string;
    areaCode: string;
    num: string;
  };
} = {};

const phoneList = [
  { customerId: "0001", areaCode: "321", num: "123-456" },
  { customerId: "0002", areaCode: "654", num: "123-456" },
];

interface PhoneInfo {
  customerId: string;
  areaCode: string;
  num: string;
}

function listToDict<T>(
  list: T[],
  idGen: (arg: T) => string
): { [k: string]: T } {
  const dict: { [k: string]: T } = {};

  list.forEach((element) => {
    const dictKey = idGen(element);
    dict[dictKey] = element;
  });

  return dict;
}

console.log(listToDict(phoneList, (item) => item.customerId));
