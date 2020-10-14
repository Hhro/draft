import numpy as np

import asm2vec.asm
import asm2vec.parse
import asm2vec.model

import glob
import sys

from typing import List, Dict
from pathlib import Path


def train(train_dir: Path):
    print(train_dir)
    training_funcs: List[asm2vec.asm.Function] = []

    for func in glob.glob(str(train_dir / "*")):
        training_funcs.append(asm2vec.parse.parse(func))

    print('# of training functions:', len(training_funcs))

    model = asm2vec.model.Asm2Vec(d=200)
    training_repo = model.make_function_repo(training_funcs)
    model.train(training_repo)
    print('Training complete.')
